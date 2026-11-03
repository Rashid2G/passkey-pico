#include "passkey/ctap2.h"
#include "passkey/ctaphid.h"
#include "passkey/cbor.h"
#include "passkey/crypto.h"
#include "passkey/pin.h"
#include "passkey/storage.h"
#include "passkey/config.h"
#include "passkey/platform.h"
#include "passkey/status.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Forward declarations */
static uint8_t ctap2_request_up(pk_ctap2_ctx_t *ctap);

static inline void ctap2_notify_processing(pk_ctap2_ctx_t *ctap) {
    if (ctap && ctap->keepalive_cb) {
        (void)ctap->keepalive_cb(ctap->keepalive_ctx, CTAPHID_STATUS_PROCESSING);
    }
}

static void clear_assertion_session(pk_ctap2_ctx_t *ctap) {
    if (ctap) {
        pk_crypto_zeroize(&ctap->assertion_session, sizeof(ctap->assertion_session));
        ctap->assertion_session.active = false;
    }
}

static uint8_t handle_get_info(
    pk_ctap2_ctx_t *ctap,
    size_t cbor_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
);

static uint8_t handle_make_credential(
    pk_ctap2_ctx_t *ctap,
    const uint8_t *cbor_buf,
    size_t cbor_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
);

static uint8_t handle_get_assertion(
    pk_ctap2_ctx_t *ctap,
    const uint8_t *cbor_buf,
    size_t cbor_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
);

static uint8_t handle_get_next_assertion(
    pk_ctap2_ctx_t *ctap,
    size_t cbor_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
);

static uint8_t handle_client_pin(
    pk_ctap2_ctx_t *ctap,
    const uint8_t *cbor_buf,
    size_t cbor_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
);

static uint8_t handle_reset(
    pk_ctap2_ctx_t *ctap,
    size_t cbor_len,
    uint8_t *resp,
    size_t *out_resp_len
);

static uint8_t handle_selection(
    pk_ctap2_ctx_t *ctap,
    uint8_t *resp,
    size_t *out_resp_len
);

static uint8_t handle_credential_mgmt(
    pk_ctap2_ctx_t *ctap,
    const uint8_t *cbor_buf,
    size_t cbor_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
);

/* Helper to request physical user presence */
static uint8_t ctap2_request_up(pk_ctap2_ctx_t *ctap) {
    if (!ctap || !ctap->platform || !ctap->platform->request_user_presence) {
        return CTAP2_ERR_OPERATION_DENIED;
    }
    pk_up_result_t res = ctap->platform->request_user_presence(
        ctap->platform->ctx,
        PK_UP_TIMEOUT_MS,
        ctap->keepalive_cb,
        ctap->keepalive_ctx
    );
    switch (res) {
        case PK_UP_CONFIRMED:
            return CTAP2_OK;
        case PK_UP_TIMEOUT:
            return CTAP2_ERR_USER_ACTION_TIMEOUT;
        case PK_UP_CANCELLED:
            return CTAP2_ERR_KEEPALIVE_CANCEL;
        case PK_UP_DENIED:
        default:
            return CTAP2_ERR_OPERATION_DENIED;
    }
}

/* Helper to derive credential HMAC-secret key and compute output */
static pk_err_t compute_hmac_secret_output(
    pk_ctap2_ctx_t *ctap,
    const pk_resident_cred_t *cred,
    const uint8_t *shared_secret,
    const uint8_t *salts,
    size_t salts_len,
    uint8_t *out_encrypted,
    size_t *out_encrypted_len
) {
    if (salts_len != 32 && salts_len != 64) {
        return PK_ERR_INVALID_ARG;
    }

    /* Derive credential-specific 32-byte HMAC-SHA-256 key:
     * HKDF-SHA-256(IKM=master_secret, salt=rp_id_hash, info="PK-HMAC-V1" || cred_random)
     */
    uint8_t info[10 + 32];
    memcpy(info, "PK-HMAC-V1", 10);
    memcpy(info + 10, cred->cred_random, 32);

    uint8_t cred_hmac_key[32];
    pk_err_t err = pk_crypto_hkdf_sha256(
        cred->rp_id_hash, 32,
        ctap->storage->state.master_secret, 32,
        info, sizeof(info),
        cred_hmac_key, sizeof(cred_hmac_key)
    );
    pk_crypto_zeroize(info, sizeof(info));
    if (err != PK_OK) {
        return err;
    }

    uint8_t plain_output[64];
    err = pk_crypto_hmac_sha256(cred_hmac_key, 32, salts, 32, plain_output);
    if (err != PK_OK) {
        pk_crypto_zeroize(cred_hmac_key, sizeof(cred_hmac_key));
        return err;
    }

    if (salts_len == 64) {
        err = pk_crypto_hmac_sha256(cred_hmac_key, 32, salts + 32, 32, plain_output + 32);
        if (err != PK_OK) {
            pk_crypto_zeroize(cred_hmac_key, sizeof(cred_hmac_key));
            pk_crypto_zeroize(plain_output, sizeof(plain_output));
            return err;
        }
    }
    pk_crypto_zeroize(cred_hmac_key, sizeof(cred_hmac_key));

    err = pk_crypto_aes256_cbc_encrypt_zero_iv(
        shared_secret,
        plain_output,
        salts_len,
        out_encrypted
    );
    pk_crypto_zeroize(plain_output, sizeof(plain_output));
    if (err == PK_OK) {
        *out_encrypted_len = salts_len;
    }
    return err;
}

/* Helper to encode assertion response map */
static pk_err_t encode_assertion_response(
    pk_cbor_writer_t *w,
    const pk_resident_cred_t *cred,
    const uint8_t *auth_data,
    size_t auth_data_len,
    const uint8_t *sig_der,
    size_t sig_der_len,
    size_t total_creds
) {
    size_t map_count = 3;
    bool include_user = (cred->user_id_len > 0);
    if (include_user) {
        map_count++;
    }
    if (total_creds > 1) {
        map_count++;
    }

    pk_cbor_encode_map_header(w, map_count);

    /* 0x01: credential PublicKeyCredentialDescriptor */
    pk_cbor_encode_uint(w, 0x01);
    pk_cbor_encode_map_header(w, 2);
    pk_cbor_encode_tstr_c(w, "id");
    pk_cbor_encode_bstr(w, cred->cred_id, sizeof(cred->cred_id));
    pk_cbor_encode_tstr_c(w, "type");
    pk_cbor_encode_tstr_c(w, "public-key");

    /* 0x02: authData */
    pk_cbor_encode_uint(w, 0x02);
    pk_cbor_encode_bstr(w, auth_data, auth_data_len);

    /* 0x03: signature */
    pk_cbor_encode_uint(w, 0x03);
    pk_cbor_encode_bstr(w, sig_der, sig_der_len);

    /* 0x04: user */
    if (include_user) {
        size_t user_fields = 1;
        if (cred->user_name[0] != '\0') {
            user_fields++;
        }
        if (cred->user_display_name[0] != '\0') {
            user_fields++;
        }

        pk_cbor_encode_uint(w, 0x04);
        pk_cbor_encode_map_header(w, user_fields);
        pk_cbor_encode_tstr_c(w, "id");
        pk_cbor_encode_bstr(w, cred->user_id, cred->user_id_len);
        if (cred->user_name[0] != '\0') {
            pk_cbor_encode_tstr_c(w, "name");
            pk_cbor_encode_tstr_c(w, cred->user_name);
        }
        if (cred->user_display_name[0] != '\0') {
            pk_cbor_encode_tstr_c(w, "displayName");
            pk_cbor_encode_tstr_c(w, cred->user_display_name);
        }
    }

    /* 0x05: numberOfCredentials */
    if (total_creds > 1) {
        pk_cbor_encode_uint(w, 0x05);
        pk_cbor_encode_uint(w, total_creds);
    }

    return w->err;
}

/* Helper to verify credential management PIN authentication */
static uint8_t verify_cred_mgmt_auth(
    pk_pin_ctx_t *pin,
    uint8_t pin_proto,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *pin_auth,
    size_t pin_auth_len
) {
    return pk_pin_verify_auth_param(
        pin, pin_proto, data, data_len, pin_auth, pin_auth_len, PK_PIN_PERM_CM, NULL
    );
}

/* Initialize CTAP2 protocol engine */
pk_err_t pk_ctap2_init(
    pk_ctap2_ctx_t *ctap,
    const pk_platform_t *platform,
    pk_crypto_ctx_t *crypto,
    pk_storage_ctx_t *storage,
    pk_pin_ctx_t *pin
) {
    if (!ctap || !platform || !crypto || !storage || !pin) {
        return PK_ERR_INVALID_ARG;
    }
    ctap->platform = platform;
    ctap->crypto = crypto;
    ctap->storage = storage;
    ctap->pin = pin;
    ctap->keepalive_cb = NULL;
    ctap->keepalive_ctx = NULL;
    clear_assertion_session(ctap);
    memset(&ctap->cred_mgmt_session, 0, sizeof(ctap->cred_mgmt_session));
    return PK_OK;
}

/* Register optional keepalive callback */
void pk_ctap2_set_keepalive_callback(
    pk_ctap2_ctx_t *ctap,
    pk_keepalive_cb_t cb,
    void *user_ctx
) {
    if (ctap) {
        ctap->keepalive_cb = cb;
        ctap->keepalive_ctx = user_ctx;
    }
}

/* CTAP2_CMD_GET_INFO (0x04) */
static uint8_t handle_get_info(
    pk_ctap2_ctx_t *ctap,
    size_t cbor_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
) {
    if (cbor_len != 0) {
        return CTAP1_ERR_INVALID_LENGTH;
    }

    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, resp + 1, max_resp_len - 1);

    /* 10 elements in canonical key order */
    pk_cbor_encode_map_header(&w, 10);

    /* 0x01: versions */
    pk_cbor_encode_uint(&w, 0x01);
    pk_cbor_encode_array_header(&w, 4);
    pk_cbor_encode_tstr_c(&w, "U2F_V2");
    pk_cbor_encode_tstr_c(&w, "FIDO_2_0");
    pk_cbor_encode_tstr_c(&w, "FIDO_2_1_PRE");
    pk_cbor_encode_tstr_c(&w, "FIDO_2_1");

    /* 0x02: extensions */
    pk_cbor_encode_uint(&w, 0x02);
    pk_cbor_encode_array_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "credProtect");
    pk_cbor_encode_tstr_c(&w, "hmac-secret");

    /* 0x03: aaguid (16 bytes) */
    pk_cbor_encode_uint(&w, 0x03);
    const uint8_t aaguid[16] = PK_AAGUID_BYTES;
    pk_cbor_encode_bstr(&w, aaguid, 16);

    /* 0x04: options map */
    pk_cbor_encode_uint(&w, 0x04);
    pk_cbor_encode_map_header(&w, 5);
    pk_cbor_encode_tstr_c(&w, "rk");
    pk_cbor_encode_bool(&w, true);
    pk_cbor_encode_tstr_c(&w, "up");
    pk_cbor_encode_bool(&w, true);
    pk_cbor_encode_tstr_c(&w, "credMgmt");
    pk_cbor_encode_bool(&w, true);
    pk_cbor_encode_tstr_c(&w, "clientPin");
    pk_cbor_encode_bool(&w, ctap->pin ? pk_pin_is_set(ctap->pin) : false);
    pk_cbor_encode_tstr_c(&w, "credentialMgmtPreview");
    pk_cbor_encode_bool(&w, true);

    /* 0x05: maxMsgSize */
    pk_cbor_encode_uint(&w, 0x05);
    pk_cbor_encode_uint(&w, PK_CTAP2_MAX_MSG_SIZE);

    /* 0x06: pinUvAuthProtocols */
    pk_cbor_encode_uint(&w, 0x06);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_uint(&w, 1);

    /* 0x07: maxCredentialCountInList */
    pk_cbor_encode_uint(&w, 0x07);
    pk_cbor_encode_uint(&w, PK_CTAP2_MAX_CRED_COUNT_LIST);

    /* 0x08: maxCredentialIdLength */
    pk_cbor_encode_uint(&w, 0x08);
    pk_cbor_encode_uint(&w, PK_CTAP2_MAX_CRED_ID_LEN);

    /* 0x0A: algorithms */
    pk_cbor_encode_uint(&w, 0x0A);
    pk_cbor_encode_array_header(&w, 1);
    pk_cbor_encode_map_header(&w, 2);
    pk_cbor_encode_tstr_c(&w, "alg");
    pk_cbor_encode_int(&w, -7);
    pk_cbor_encode_tstr_c(&w, "type");
    pk_cbor_encode_tstr_c(&w, "public-key");

    /* 0x0E: firmwareVersion */
    pk_cbor_encode_uint(&w, 0x0E);
    uint32_t fw_ver = ((uint32_t)PK_FIRMWARE_VERSION_MAJOR << 16) |
                      ((uint32_t)PK_FIRMWARE_VERSION_MINOR << 8) |
                      ((uint32_t)PK_FIRMWARE_VERSION_BUILD);
    pk_cbor_encode_uint(&w, fw_ver);

    if (w.err != PK_OK) {
        return (w.err == PK_ERR_BUFFER_TOO_SMALL) ? CTAP2_ERR_LIMIT_EXCEEDED : CTAP2_ERR_PROCESSING;
    }

    resp[0] = CTAP2_OK;
    *out_resp_len = 1 + w.offset;
    return CTAP2_OK;
}

/* CTAP2_CMD_MAKE_CREDENTIAL (0x01) */
static uint8_t handle_make_credential(
    pk_ctap2_ctx_t *ctap,
    const uint8_t *cbor_buf,
    size_t cbor_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
) {
    if (cbor_len == 0) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, cbor_buf, cbor_len);

    size_t map_count = 0;
    if (pk_cbor_decode_map_header(&r, &map_count) != PK_OK) {
        return CTAP2_ERR_INVALID_CBOR;
    }

    const uint8_t *client_data_hash = NULL;
    size_t client_data_hash_len = 0;

    const char *rp_id = NULL;
    size_t rp_id_len = 0;

    const uint8_t *user_id = NULL;
    size_t user_id_len = 0;
    const char *user_name = NULL;
    size_t user_name_len = 0;
    const char *user_display_name = NULL;
    size_t user_display_name_len = 0;

    bool has_pub_key_cred_params = false;
    bool es256_supported = false;

    typedef struct {
        const uint8_t *id;
        size_t id_len;
    } cred_desc_t;
    cred_desc_t exclude_list[PK_CTAP2_MAX_CRED_COUNT_LIST];
    size_t exclude_list_count = 0;

    bool ext_hmac_secret = false;
    uint8_t ext_cred_protect = 0;

    bool opt_rk = false;
    bool opt_up = true;
    bool opt_up_present = false;
    bool opt_uv = false;
    bool opt_uv_present = false;

    const uint8_t *pin_auth = NULL;
    size_t pin_auth_len = 0;
    bool pin_auth_present = false;

    uint64_t pin_proto = 0;
    bool pin_proto_present = false;

    for (size_t i = 0; i < map_count; i++) {
        uint64_t key = 0;
        if (pk_cbor_decode_uint(&r, &key) != PK_OK) {
            return CTAP2_ERR_INVALID_CBOR;
        }

        switch (key) {
            case 0x01: { /* clientDataHash */
                if (pk_cbor_decode_bstr(&r, &client_data_hash, &client_data_hash_len) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            }
            case 0x02: { /* rp */
                size_t rp_map_count = 0;
                if (pk_cbor_decode_map_header(&r, &rp_map_count) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                for (size_t j = 0; j < rp_map_count; j++) {
                    const char *k_str = NULL;
                    size_t k_len = 0;
                    if (pk_cbor_decode_tstr(&r, &k_str, &k_len) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                    if (k_len == 2 && memcmp(k_str, "id", 2) == 0) {
                        if (pk_cbor_decode_tstr(&r, &rp_id, &rp_id_len) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    } else {
                        if (pk_cbor_skip_item(&r) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    }
                }
                break;
            }
            case 0x03: { /* user */
                size_t user_map_count = 0;
                if (pk_cbor_decode_map_header(&r, &user_map_count) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                for (size_t j = 0; j < user_map_count; j++) {
                    const char *k_str = NULL;
                    size_t k_len = 0;
                    if (pk_cbor_decode_tstr(&r, &k_str, &k_len) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                    if (k_len == 2 && memcmp(k_str, "id", 2) == 0) {
                        if (pk_cbor_decode_bstr(&r, &user_id, &user_id_len) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    } else if (k_len == 4 && memcmp(k_str, "name", 4) == 0) {
                        if (pk_cbor_decode_tstr(&r, &user_name, &user_name_len) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    } else if (k_len == 11 && memcmp(k_str, "displayName", 11) == 0) {
                        if (pk_cbor_decode_tstr(&r, &user_display_name, &user_display_name_len) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    } else {
                        if (pk_cbor_skip_item(&r) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    }
                }
                break;
            }
            case 0x04: { /* pubKeyCredParams */
                has_pub_key_cred_params = true;
                size_t params_count = 0;
                if (pk_cbor_decode_array_header(&r, &params_count) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                if (params_count == 0) {
                    return CTAP2_ERR_MISSING_PARAMETER;
                }
                for (size_t j = 0; j < params_count; j++) {
                    size_t param_map_count = 0;
                    if (pk_cbor_decode_map_header(&r, &param_map_count) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                    bool is_public_key = false;
                    int64_t alg = 0;
                    bool alg_present = false;
                    for (size_t k = 0; k < param_map_count; k++) {
                        const char *pk_str = NULL;
                        size_t pk_len = 0;
                        if (pk_cbor_decode_tstr(&r, &pk_str, &pk_len) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                        if (pk_len == 4 && memcmp(pk_str, "type", 4) == 0) {
                            const char *tv = NULL;
                            size_t tv_len = 0;
                            if (pk_cbor_decode_tstr(&r, &tv, &tv_len) != PK_OK) {
                                return CTAP2_ERR_INVALID_CBOR;
                            }
                            if (tv_len == 10 && memcmp(tv, "public-key", 10) == 0) {
                                is_public_key = true;
                            }
                        } else if (pk_len == 3 && memcmp(pk_str, "alg", 3) == 0) {
                            if (pk_cbor_decode_int(&r, &alg) != PK_OK) {
                                return CTAP2_ERR_INVALID_CBOR;
                            }
                            alg_present = true;
                        } else {
                            if (pk_cbor_skip_item(&r) != PK_OK) {
                                return CTAP2_ERR_INVALID_CBOR;
                            }
                        }
                    }
                    if (is_public_key && alg_present && alg == -7) {
                        es256_supported = true;
                    }
                }
                break;
            }
            case 0x05: { /* excludeList */
                size_t ex_count = 0;
                if (pk_cbor_decode_array_header(&r, &ex_count) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                for (size_t j = 0; j < ex_count; j++) {
                    size_t desc_map_count = 0;
                    if (pk_cbor_decode_map_header(&r, &desc_map_count) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                    bool is_pubkey = false;
                    const uint8_t *desc_id = NULL;
                    size_t desc_id_len = 0;
                    for (size_t k = 0; k < desc_map_count; k++) {
                        const char *dk = NULL;
                        size_t dk_len = 0;
                        if (pk_cbor_decode_tstr(&r, &dk, &dk_len) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                        if (dk_len == 4 && memcmp(dk, "type", 4) == 0) {
                            const char *tv = NULL;
                            size_t tv_len = 0;
                            if (pk_cbor_decode_tstr(&r, &tv, &tv_len) != PK_OK) {
                                return CTAP2_ERR_INVALID_CBOR;
                            }
                            if (tv_len == 10 && memcmp(tv, "public-key", 10) == 0) {
                                is_pubkey = true;
                            }
                        } else if (dk_len == 2 && memcmp(dk, "id", 2) == 0) {
                            if (pk_cbor_decode_bstr(&r, &desc_id, &desc_id_len) != PK_OK) {
                                return CTAP2_ERR_INVALID_CBOR;
                            }
                        } else {
                            if (pk_cbor_skip_item(&r) != PK_OK) {
                                return CTAP2_ERR_INVALID_CBOR;
                            }
                        }
                    }
                    if (is_pubkey && desc_id && exclude_list_count < PK_CTAP2_MAX_CRED_COUNT_LIST) {
                        exclude_list[exclude_list_count].id = desc_id;
                        exclude_list[exclude_list_count].id_len = desc_id_len;
                        exclude_list_count++;
                    }
                }
                break;
            }
            case 0x06: { /* extensions */
                size_t ext_map_count = 0;
                if (pk_cbor_decode_map_header(&r, &ext_map_count) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                for (size_t j = 0; j < ext_map_count; j++) {
                    const char *ek = NULL;
                    size_t ek_len = 0;
                    if (pk_cbor_decode_tstr(&r, &ek, &ek_len) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                    if (ek_len == 11 && memcmp(ek, "hmac-secret", 11) == 0) {
                        if (pk_cbor_decode_bool(&r, &ext_hmac_secret) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    } else if (ek_len == 11 && memcmp(ek, "credProtect", 11) == 0) {
                        uint64_t cp_val = 0;
                        if (pk_cbor_decode_uint(&r, &cp_val) != PK_OK || cp_val < 1 || cp_val > 3) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                        ext_cred_protect = (uint8_t)cp_val;
                    } else {
                        if (pk_cbor_skip_item(&r) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    }
                }
                break;
            }
            case 0x07: { /* options */
                size_t opt_map_count = 0;
                if (pk_cbor_decode_map_header(&r, &opt_map_count) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                for (size_t j = 0; j < opt_map_count; j++) {
                    const char *ok = NULL;
                    size_t ok_len = 0;
                    if (pk_cbor_decode_tstr(&r, &ok, &ok_len) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                    if (ok_len == 2 && memcmp(ok, "rk", 2) == 0) {
                        if (pk_cbor_decode_bool(&r, &opt_rk) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    } else if (ok_len == 2 && memcmp(ok, "up", 2) == 0) {
                        if (pk_cbor_decode_bool(&r, &opt_up) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                        opt_up_present = true;
                    } else if (ok_len == 2 && memcmp(ok, "uv", 2) == 0) {
                        if (pk_cbor_decode_bool(&r, &opt_uv) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                        opt_uv_present = true;
                    } else {
                        if (pk_cbor_skip_item(&r) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    }
                }
                break;
            }
            case 0x08: { /* pinUvAuthParam */
                pin_auth_present = true;
                if (pk_cbor_decode_bstr(&r, &pin_auth, &pin_auth_len) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            }
            case 0x09: { /* pinUvAuthProtocol */
                pin_proto_present = true;
                if (pk_cbor_decode_uint(&r, &pin_proto) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            }
            default: {
                if (pk_cbor_skip_item(&r) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            }
        }
    }

    /* Parameter validation */
    if (!client_data_hash) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (client_data_hash_len != 32) {
        return CTAP2_ERR_INVALID_CBOR;
    }
    if (!rp_id || rp_id_len == 0) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!user_id || user_id_len < 1 || user_id_len > PK_USER_ID_MAX_LEN) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!has_pub_key_cred_params) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!es256_supported) {
        return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }
    if (opt_up_present && !opt_up) {
        return CTAP2_ERR_INVALID_OPTION;
    }
    if (opt_uv_present && opt_uv) {
        return CTAP2_ERR_UNSUPPORTED_OPTION;
    }

    uint8_t rp_id_hash[32];
    pk_crypto_sha256((const uint8_t *)rp_id, rp_id_len, rp_id_hash);

    /* Verify PIN / UV authorization */
    bool uv_flag = false;
    if (pin_auth_present) {
        if (pin_auth_len == 0) {
            uint8_t up_res = ctap2_request_up(ctap);
            if (up_res != CTAP2_OK) {
                return up_res;
            }
            if (!ctap->pin || !pk_pin_is_set(ctap->pin)) {
                return CTAP2_ERR_PIN_NOT_SET;
            } else {
                return CTAP2_ERR_PIN_INVALID;
            }
        }
        if (!pin_proto_present || pin_proto != 1) {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        uint8_t pin_err = pk_pin_verify_auth_param(
            ctap->pin,
            (uint8_t)pin_proto,
            client_data_hash,
            32,
            pin_auth,
            pin_auth_len,
            PK_PIN_PERM_MC,
            rp_id_hash
        );
        if (pin_err != CTAP2_OK) {
            return pin_err;
        }
        uv_flag = true;
    } else {
        if (ctap->pin && pk_pin_is_set(ctap->pin)) {
            return CTAP2_ERR_PIN_REQUIRED;
        }
    }

    /* Check excludeList */
    bool cred_excluded = false;
    for (size_t i = 0; i < exclude_list_count; i++) {
        const uint8_t *cid = exclude_list[i].id;
        size_t cid_len = exclude_list[i].id_len;
        if (cid_len == PK_CRED_ID_RESIDENT_LEN) {
            pk_resident_cred_t found_cred;
            if (pk_storage_find_by_id(ctap->storage, rp_id_hash, cid, cid_len, &found_cred) == PK_OK) {
                cred_excluded = true;
                pk_crypto_zeroize(&found_cred, sizeof(found_cred));
                break;
            }
        }
        if (cid_len == PK_CRED_ID_NONRESIDENT_LEN) {
            uint8_t dummy_rnd[32];
            if (pk_crypto_unseal_nonresident_cred_id(ctap->storage->state.cred_mac_key, rp_id_hash, cid, dummy_rnd) == PK_OK) {
                cred_excluded = true;
                pk_crypto_zeroize(dummy_rnd, sizeof(dummy_rnd));
                break;
            }
        }
    }
    if (cred_excluded) {
        uint8_t up_res = ctap2_request_up(ctap);
        if (up_res != CTAP2_OK) {
            return up_res;
        }
        return CTAP2_ERR_CREDENTIAL_EXCLUDED;
    }

    /* Request physical user presence */
    uint8_t up_res = ctap2_request_up(ctap);
    if (up_res != CTAP2_OK) {
        return up_res;
    }

    ctap2_notify_processing(ctap);

    /* Increment signature counter */
    uint32_t sign_cnt = 0;
    if (pk_storage_next_sign_counter(ctap->storage, &sign_cnt) != PK_OK) {
        return CTAP2_ERR_PROCESSING;
    }

    ctap2_notify_processing(ctap);

    /* Generate credential */
    uint8_t priv_key[PK_P256_PRIVKEY_LEN];
    pk_p256_pubkey_t pub_key;
    uint8_t cred_id[PK_CRED_ID_RESIDENT_LEN];

    if (opt_rk) {
        pk_resident_cred_t cred;
        memset(&cred, 0, sizeof(cred));
        cred.active = true;
        if (pk_crypto_seal_nonresident_cred_id(ctap->crypto, ctap->storage->state.cred_mac_key, rp_id_hash, cred.cred_id, cred.cred_random) != PK_OK) {
            return CTAP2_ERR_PROCESSING;
        }
        memcpy(cred_id, cred.cred_id, sizeof(cred_id));
        if (pk_crypto_derive_credential_keypair(ctap->storage->state.master_secret, rp_id_hash, cred.cred_random, cred.priv_key, &cred.pub_key) != PK_OK) {
            return CTAP2_ERR_PROCESSING;
        }
        ctap2_notify_processing(ctap);
        memcpy(priv_key, cred.priv_key, PK_P256_PRIVKEY_LEN);
        memcpy(&pub_key, &cred.pub_key, sizeof(pub_key));
        memcpy(cred.rp_id_hash, rp_id_hash, 32);

        size_t cpy_rp_len = rp_id_len < (PK_RP_ID_MAX_LEN - 1) ? rp_id_len : (PK_RP_ID_MAX_LEN - 1);
        memcpy(cred.rp_id, rp_id, cpy_rp_len);
        cred.rp_id[cpy_rp_len] = '\0';

        memcpy(cred.user_id, user_id, user_id_len);
        cred.user_id_len = (uint8_t)user_id_len;

        if (user_name && user_name_len > 0) {
            size_t cpy_un = user_name_len < (PK_USER_NAME_MAX_LEN - 1) ? user_name_len : (PK_USER_NAME_MAX_LEN - 1);
            memcpy(cred.user_name, user_name, cpy_un);
            cred.user_name[cpy_un] = '\0';
        }
        if (user_display_name && user_display_name_len > 0) {
            size_t cpy_ud = user_display_name_len < (PK_USER_DISPLAY_MAX_LEN - 1) ? user_display_name_len : (PK_USER_DISPLAY_MAX_LEN - 1);
            memcpy(cred.user_display_name, user_display_name, cpy_ud);
            cred.user_display_name[cpy_ud] = '\0';
        }
        cred.hmac_secret_enabled = ext_hmac_secret;
        cred.cred_Provide_up_uv_flags = (ext_cred_protect != 0) ? ext_cred_protect : 1U;

        pk_err_t s_err = pk_storage_save_credential(ctap->storage, &cred);
        ctap2_notify_processing(ctap);
        if (s_err == PK_ERR_FULL) {
            pk_crypto_zeroize(priv_key, sizeof(priv_key));
            pk_crypto_zeroize(&cred, sizeof(cred));
            return CTAP2_ERR_KEY_STORE_FULL;
        } else if (s_err != PK_OK) {
            pk_crypto_zeroize(priv_key, sizeof(priv_key));
            pk_crypto_zeroize(&cred, sizeof(cred));
            return CTAP2_ERR_PROCESSING;
        }
        pk_crypto_zeroize(&cred, sizeof(cred));
    } else {
        uint8_t cred_random[32];
        if (pk_crypto_seal_nonresident_cred_id(ctap->crypto, ctap->storage->state.cred_mac_key, rp_id_hash, cred_id, cred_random) != PK_OK) {
            return CTAP2_ERR_PROCESSING;
        }
        if (pk_crypto_derive_credential_keypair(ctap->storage->state.master_secret, rp_id_hash, cred_random, priv_key, &pub_key) != PK_OK) {
            pk_crypto_zeroize(cred_random, sizeof(cred_random));
            return CTAP2_ERR_PROCESSING;
        }
        ctap2_notify_processing(ctap);
        pk_crypto_zeroize(cred_random, sizeof(cred_random));
    }

    /* Build authData */
    uint8_t auth_data[300];
    memcpy(&auth_data[0], rp_id_hash, 32);

    uint8_t flags = CTAP2_AUTH_DATA_FLAG_UP | CTAP2_AUTH_DATA_FLAG_AT;
    if (uv_flag) {
        flags |= CTAP2_AUTH_DATA_FLAG_UV;
    }
    if (ext_hmac_secret || ext_cred_protect != 0) {
        flags |= CTAP2_AUTH_DATA_FLAG_ED;
    }
    auth_data[32] = flags;

    auth_data[33] = (uint8_t)(sign_cnt >> 24);
    auth_data[34] = (uint8_t)(sign_cnt >> 16);
    auth_data[35] = (uint8_t)(sign_cnt >> 8);
    auth_data[36] = (uint8_t)(sign_cnt);

    const uint8_t aaguid[16] = PK_AAGUID_BYTES;
    memcpy(&auth_data[37], aaguid, 16);

    auth_data[53] = 0x00;
    auth_data[54] = 0x40; /* 64 bytes */
    memcpy(&auth_data[55], cred_id, 64);

    pk_cbor_writer_t cose_w;
    pk_cbor_writer_init(&cose_w, &auth_data[119], sizeof(auth_data) - 119);
    if (pk_cbor_encode_cose_p256_pubkey(&cose_w, &pub_key, false) != PK_OK) {
        pk_crypto_zeroize(priv_key, sizeof(priv_key));
        return CTAP2_ERR_PROCESSING;
    }
    size_t auth_data_len = 119 + cose_w.offset;

    if (ext_hmac_secret || ext_cred_protect != 0) {
        pk_cbor_writer_t ext_w;
        pk_cbor_writer_init(&ext_w, &auth_data[auth_data_len], sizeof(auth_data) - auth_data_len);
        size_t ext_entries = (ext_hmac_secret ? 1 : 0) + (ext_cred_protect != 0 ? 1 : 0);
        pk_cbor_encode_map_header(&ext_w, ext_entries);
        if (ext_cred_protect != 0) {
            pk_cbor_encode_tstr_c(&ext_w, "credProtect");
            pk_cbor_encode_uint(&ext_w, ext_cred_protect);
        }
        if (ext_hmac_secret) {
            pk_cbor_encode_tstr_c(&ext_w, "hmac-secret");
            pk_cbor_encode_bool(&ext_w, true);
        }
        if (ext_w.err != PK_OK) {
            pk_crypto_zeroize(priv_key, sizeof(priv_key));
            return CTAP2_ERR_PROCESSING;
        }
        auth_data_len += ext_w.offset;
    }

    /* Compute sig_hash = SHA-256(authData || clientDataHash) */
    uint8_t sig_hash[32];
    pk_crypto_sha256_two(auth_data, auth_data_len, client_data_hash, 32, sig_hash);

    /* Attestation cert and private key */
    uint8_t att_priv[PK_P256_PRIVKEY_LEN];
    uint8_t cert_der[600];
    size_t cert_der_len = 0;
    if (pk_crypto_build_attestation_cert_der(ctap->crypto, ctap->storage->state.attestation_seed, att_priv, cert_der, sizeof(cert_der), &cert_der_len) != PK_OK) {
        pk_crypto_zeroize(priv_key, sizeof(priv_key));
        return CTAP2_ERR_PROCESSING;
    }
    ctap2_notify_processing(ctap);

    uint8_t sig_der[PK_ECDSA_MAX_DER_SIG_LEN];
    size_t sig_der_len = 0;
    if (pk_crypto_p256_sign_der(ctap->crypto, att_priv, sig_hash, sig_der, &sig_der_len) != PK_OK) {
        pk_crypto_zeroize(priv_key, sizeof(priv_key));
        pk_crypto_zeroize(att_priv, sizeof(att_priv));
        return CTAP2_ERR_PROCESSING;
    }
    ctap2_notify_processing(ctap);

    pk_crypto_zeroize(priv_key, sizeof(priv_key));
    pk_crypto_zeroize(att_priv, sizeof(att_priv));

    /* Encode MakeCredential response */
    pk_cbor_writer_t resp_w;
    pk_cbor_writer_init(&resp_w, resp + 1, max_resp_len - 1);
    pk_cbor_encode_map_header(&resp_w, 3);

    /* 0x01: fmt */
    pk_cbor_encode_uint(&resp_w, 0x01);
    pk_cbor_encode_tstr_c(&resp_w, "packed");

    /* 0x02: authData */
    pk_cbor_encode_uint(&resp_w, 0x02);
    pk_cbor_encode_bstr(&resp_w, auth_data, auth_data_len);

    /* 0x03: attStmt */
    pk_cbor_encode_uint(&resp_w, 0x03);
    pk_cbor_encode_map_header(&resp_w, 3);
    pk_cbor_encode_tstr_c(&resp_w, "alg");
    pk_cbor_encode_int(&resp_w, -7);
    pk_cbor_encode_tstr_c(&resp_w, "sig");
    pk_cbor_encode_bstr(&resp_w, sig_der, sig_der_len);
    pk_cbor_encode_tstr_c(&resp_w, "x5c");
    pk_cbor_encode_array_header(&resp_w, 1);
    pk_cbor_encode_bstr(&resp_w, cert_der, cert_der_len);

    if (resp_w.err != PK_OK) {
        return (resp_w.err == PK_ERR_BUFFER_TOO_SMALL) ? CTAP2_ERR_LIMIT_EXCEEDED : CTAP2_ERR_PROCESSING;
    }

    resp[0] = CTAP2_OK;
    *out_resp_len = 1 + resp_w.offset;
    return CTAP2_OK;
}

/* CTAP2_CMD_GET_ASSERTION (0x02) */
static uint8_t handle_get_assertion(
    pk_ctap2_ctx_t *ctap,
    const uint8_t *cbor_buf,
    size_t cbor_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
) {
    if (cbor_len == 0) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, cbor_buf, cbor_len);

    size_t map_count = 0;
    if (pk_cbor_decode_map_header(&r, &map_count) != PK_OK) {
        return CTAP2_ERR_INVALID_CBOR;
    }

    const char *rp_id = NULL;
    size_t rp_id_len = 0;

    const uint8_t *client_data_hash = NULL;
    size_t client_data_hash_len = 0;

    typedef struct {
        const uint8_t *id;
        size_t id_len;
    } cred_desc_t;
    cred_desc_t allow_list[PK_CTAP2_MAX_CRED_COUNT_LIST];
    size_t allow_list_count = 0;
    bool allow_list_present = false;

    bool opt_up = true;
    bool opt_uv = false;
    bool opt_uv_present = false;

    const uint8_t *pin_auth = NULL;
    size_t pin_auth_len = 0;
    bool pin_auth_present = false;

    uint64_t pin_proto = 0;
    bool pin_proto_present = false;

    /* hmac-secret extension parameters */
    bool ext_hmac_secret_requested = false;
    pk_p256_pubkey_t ext_key_agreement;
    bool ext_has_key_agreement = false;
    const uint8_t *ext_salt_enc = NULL;
    size_t ext_salt_enc_len = 0;
    const uint8_t *ext_salt_auth = NULL;
    size_t ext_salt_auth_len = 0;
    uint64_t ext_pin_uv_proto = 1;

    for (size_t i = 0; i < map_count; i++) {
        uint64_t key = 0;
        if (pk_cbor_decode_uint(&r, &key) != PK_OK) {
            return CTAP2_ERR_INVALID_CBOR;
        }

        switch (key) {
            case 0x01: { /* rpId */
                if (pk_cbor_decode_tstr(&r, &rp_id, &rp_id_len) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            }
            case 0x02: { /* clientDataHash */
                if (pk_cbor_decode_bstr(&r, &client_data_hash, &client_data_hash_len) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            }
            case 0x03: { /* allowList */
                allow_list_present = true;
                size_t arr_len = 0;
                if (pk_cbor_decode_array_header(&r, &arr_len) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                for (size_t j = 0; j < arr_len; j++) {
                    size_t desc_map_count = 0;
                    if (pk_cbor_decode_map_header(&r, &desc_map_count) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                    bool is_pubkey = false;
                    const uint8_t *desc_id = NULL;
                    size_t desc_id_len = 0;
                    for (size_t k = 0; k < desc_map_count; k++) {
                        const char *dk = NULL;
                        size_t dk_len = 0;
                        if (pk_cbor_decode_tstr(&r, &dk, &dk_len) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                        if (dk_len == 4 && memcmp(dk, "type", 4) == 0) {
                            const char *tv = NULL;
                            size_t tv_len = 0;
                            if (pk_cbor_decode_tstr(&r, &tv, &tv_len) != PK_OK) {
                                return CTAP2_ERR_INVALID_CBOR;
                            }
                            if (tv_len == 10 && memcmp(tv, "public-key", 10) == 0) {
                                is_pubkey = true;
                            }
                        } else if (dk_len == 2 && memcmp(dk, "id", 2) == 0) {
                            if (pk_cbor_decode_bstr(&r, &desc_id, &desc_id_len) != PK_OK) {
                                return CTAP2_ERR_INVALID_CBOR;
                            }
                        } else {
                            if (pk_cbor_skip_item(&r) != PK_OK) {
                                return CTAP2_ERR_INVALID_CBOR;
                            }
                        }
                    }
                    if (is_pubkey && desc_id && allow_list_count < PK_CTAP2_MAX_CRED_COUNT_LIST) {
                        allow_list[allow_list_count].id = desc_id;
                        allow_list[allow_list_count].id_len = desc_id_len;
                        allow_list_count++;
                    }
                }
                break;
            }
            case 0x04: { /* extensions */
                size_t ext_map_len = 0;
                if (pk_cbor_decode_map_header(&r, &ext_map_len) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                for (size_t j = 0; j < ext_map_len; j++) {
                    const char *ek = NULL;
                    size_t ek_len = 0;
                    if (pk_cbor_decode_tstr(&r, &ek, &ek_len) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                    if (ek_len == 11 && memcmp(ek, "hmac-secret", 11) == 0) {
                        ext_hmac_secret_requested = true;
                        size_t hmac_map_len = 0;
                        if (pk_cbor_decode_map_header(&r, &hmac_map_len) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                        for (size_t h = 0; h < hmac_map_len; h++) {
                            uint64_t hkey = 0;
                            if (pk_cbor_decode_uint(&r, &hkey) != PK_OK) {
                                return CTAP2_ERR_INVALID_CBOR;
                            }
                            if (hkey == 0x01) {
                                if (pk_cbor_decode_cose_p256_pubkey(&r, &ext_key_agreement) != PK_OK) {
                                    return CTAP2_ERR_INVALID_CBOR;
                                }
                                ext_has_key_agreement = true;
                            } else if (hkey == 0x02) {
                                if (pk_cbor_decode_bstr(&r, &ext_salt_enc, &ext_salt_enc_len) != PK_OK) {
                                    return CTAP2_ERR_INVALID_CBOR;
                                }
                            } else if (hkey == 0x03) {
                                if (pk_cbor_decode_bstr(&r, &ext_salt_auth, &ext_salt_auth_len) != PK_OK) {
                                    return CTAP2_ERR_INVALID_CBOR;
                                }
                            } else if (hkey == 0x04) {
                                if (pk_cbor_decode_uint(&r, &ext_pin_uv_proto) != PK_OK) {
                                    return CTAP2_ERR_INVALID_CBOR;
                                }
                            } else {
                                if (pk_cbor_skip_item(&r) != PK_OK) {
                                    return CTAP2_ERR_INVALID_CBOR;
                                }
                            }
                        }
                    } else {
                        if (pk_cbor_skip_item(&r) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    }
                }
                break;
            }
            case 0x05: { /* options */
                size_t opt_map_count = 0;
                if (pk_cbor_decode_map_header(&r, &opt_map_count) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                for (size_t j = 0; j < opt_map_count; j++) {
                    const char *ok = NULL;
                    size_t ok_len = 0;
                    if (pk_cbor_decode_tstr(&r, &ok, &ok_len) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                    if (ok_len == 2 && memcmp(ok, "up", 2) == 0) {
                        if (pk_cbor_decode_bool(&r, &opt_up) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    } else if (ok_len == 2 && memcmp(ok, "uv", 2) == 0) {
                        if (pk_cbor_decode_bool(&r, &opt_uv) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                        opt_uv_present = true;
                    } else {
                        if (pk_cbor_skip_item(&r) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                    }
                }
                break;
            }
            case 0x06: { /* pinUvAuthParam */
                pin_auth_present = true;
                if (pk_cbor_decode_bstr(&r, &pin_auth, &pin_auth_len) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            }
            case 0x07: { /* pinUvAuthProtocol */
                pin_proto_present = true;
                if (pk_cbor_decode_uint(&r, &pin_proto) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            }
            default: {
                if (pk_cbor_skip_item(&r) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            }
        }
    }

    if (!rp_id || rp_id_len == 0) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!client_data_hash) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (client_data_hash_len != 32) {
        return CTAP2_ERR_INVALID_CBOR;
    }
    if (opt_uv_present && opt_uv) {
        return CTAP2_ERR_UNSUPPORTED_OPTION;
    }

    uint8_t rp_id_hash[32];
    pk_crypto_sha256((const uint8_t *)rp_id, rp_id_len, rp_id_hash);

    /* Verify PIN / UV authorization if provided */
    bool uv_flag = false;
    if (pin_auth_present) {
        if (pin_auth_len == 0) {
            uint8_t up_res = ctap2_request_up(ctap);
            if (up_res != CTAP2_OK) {
                return up_res;
            }
            if (!ctap->pin || !pk_pin_is_set(ctap->pin)) {
                return CTAP2_ERR_PIN_NOT_SET;
            } else {
                return CTAP2_ERR_PIN_INVALID;
            }
        }
        if (!pin_proto_present || pin_proto != 1) {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        uint8_t pin_err = pk_pin_verify_auth_param(
            ctap->pin,
            (uint8_t)pin_proto,
            client_data_hash,
            32,
            pin_auth,
            pin_auth_len,
            PK_PIN_PERM_GA,
            rp_id_hash
        );
        if (pin_err != CTAP2_OK) {
            return pin_err;
        }
        uv_flag = true;
    }

    /* Validate hmac-secret extension parameters if requested */
    uint8_t hmac_shared_secret[32];
    uint8_t decrypted_salts[64];
    size_t decrypted_salts_len = 0;

    if (ext_hmac_secret_requested) {
        if (!ext_has_key_agreement || !ext_salt_enc || !ext_salt_auth ||
            (ext_salt_enc_len != 32 && ext_salt_enc_len != 64) || ext_salt_auth_len != 16 ||
            ext_pin_uv_proto != 1) {
            return CTAP2_ERR_INVALID_CBOR;
        }

        if (!ctap->crypto->pin_ecdh_valid) {
            if (pk_crypto_regenerate_pin_keyagreement(ctap->crypto) != PK_OK) {
                return CTAP2_ERR_PROCESSING;
            }
        }

        if (pk_crypto_p256_ecdh_shared_secret_sha256(
                ctap->crypto,
                ctap->crypto->pin_ecdh_priv,
                &ext_key_agreement,
                hmac_shared_secret) != PK_OK) {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }

        /* Verify saltAuth = LEFT(HMAC-SHA-256(hmac_shared_secret, ext_salt_enc), 16) */
        uint8_t expected_auth[32];
        if (pk_crypto_hmac_sha256(hmac_shared_secret, 32, ext_salt_enc, ext_salt_enc_len, expected_auth) != PK_OK) {
            pk_crypto_zeroize(hmac_shared_secret, sizeof(hmac_shared_secret));
            return CTAP2_ERR_PROCESSING;
        }
        bool auth_ok = pk_crypto_consttime_eq(expected_auth, ext_salt_auth, 16);
        pk_crypto_zeroize(expected_auth, sizeof(expected_auth));
        if (!auth_ok) {
            pk_crypto_zeroize(hmac_shared_secret, sizeof(hmac_shared_secret));
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }

        /* Decrypt saltEnc using AES-256-CBC Zero-IV */
        if (pk_crypto_aes256_cbc_decrypt_zero_iv(
                hmac_shared_secret,
                ext_salt_enc,
                ext_salt_enc_len,
                decrypted_salts) != PK_OK) {
            pk_crypto_zeroize(hmac_shared_secret, sizeof(hmac_shared_secret));
            return CTAP2_ERR_PROCESSING;
        }
        decrypted_salts_len = ext_salt_enc_len;
    }

    /* Locate matching credentials */
    size_t match_count = 0;
    bool uv_required_found = false;
    if (allow_list_present) {
        for (size_t i = 0; i < allow_list_count && match_count < 8; i++) {
            const uint8_t *cid = allow_list[i].id;
            size_t cid_len = allow_list[i].id_len;
            if (cid_len != PK_CRED_ID_RESIDENT_LEN && cid_len != PK_CRED_ID_NONRESIDENT_LEN) {
                continue;
            }

            pk_resident_cred_t resident_cred;
            if (pk_storage_find_by_id(ctap->storage, rp_id_hash, cid, cid_len, &resident_cred) == PK_OK) {
                /* Check credProtect policy */
                if (resident_cred.cred_Provide_up_uv_flags == 2 && !allow_list_present && !uv_flag) {
                    pk_crypto_zeroize(&resident_cred, sizeof(resident_cred));
                    continue;
                }
                if (resident_cred.cred_Provide_up_uv_flags == 3 && !uv_flag) {
                    uv_required_found = true;
                    pk_crypto_zeroize(&resident_cred, sizeof(resident_cred));
                    continue;
                }

                ctap->assertion_session.creds[match_count] = resident_cred;
                pk_crypto_zeroize(&resident_cred, sizeof(resident_cred));
                match_count++;
                continue;
            }

            uint8_t cred_random[32];
            if (pk_crypto_unseal_nonresident_cred_id(ctap->storage->state.cred_mac_key, rp_id_hash, cid, cred_random) == PK_OK) {
                pk_resident_cred_t *nr = &ctap->assertion_session.creds[match_count];
                memset(nr, 0, sizeof(*nr));
                nr->active = true;
                memcpy(nr->cred_id, cid, PK_CRED_ID_NONRESIDENT_LEN);
                memcpy(nr->rp_id_hash, rp_id_hash, 32);
                memcpy(nr->cred_random, cred_random, 32);
                nr->user_id_len = 0;
                nr->hmac_secret_enabled = true;
                nr->cred_Provide_up_uv_flags = 1;
                if (pk_crypto_derive_credential_keypair(ctap->storage->state.master_secret, rp_id_hash, cred_random, nr->priv_key, &nr->pub_key) == PK_OK) {
                    match_count++;
                }
                ctap2_notify_processing(ctap);
                pk_crypto_zeroize(cred_random, sizeof(cred_random));
            }
        }
    } else {
        pk_resident_cred_t raw_creds[8];
        size_t raw_count = 0;
        pk_storage_find_by_rp(ctap->storage, rp_id_hash, raw_creds, 8, &raw_count);
        for (size_t i = 0; i < raw_count; i++) {
            /* credProtect enforcement */
            if (raw_creds[i].cred_Provide_up_uv_flags == 2 && !uv_flag) {
                pk_crypto_zeroize(&raw_creds[i], sizeof(raw_creds[i]));
                continue;
            }
            if (raw_creds[i].cred_Provide_up_uv_flags == 3 && !uv_flag) {
                pk_crypto_zeroize(&raw_creds[i], sizeof(raw_creds[i]));
                continue;
            }
            ctap->assertion_session.creds[match_count++] = raw_creds[i];
            pk_crypto_zeroize(&raw_creds[i], sizeof(raw_creds[i]));
        }
    }

    /* If no credentials match: wait for user presence if UP requested, then return CTAP2_ERR_NO_CREDENTIALS */
    if (match_count == 0) {
        if (ext_hmac_secret_requested) {
            pk_crypto_zeroize(hmac_shared_secret, sizeof(hmac_shared_secret));
            pk_crypto_zeroize(decrypted_salts, sizeof(decrypted_salts));
        }
        if (uv_required_found) {
            return CTAP2_ERR_PIN_REQUIRED;
        }
        if (opt_up) {
            uint8_t up_res = ctap2_request_up(ctap);
            if (up_res != CTAP2_OK) {
                return up_res;
            }
        }
        return CTAP2_ERR_NO_CREDENTIALS;
    }

    /* Request user presence */
    bool up_flag = false;
    if (opt_up) {
        uint8_t up_res = ctap2_request_up(ctap);
        if (up_res != CTAP2_OK) {
            if (ext_hmac_secret_requested) {
                pk_crypto_zeroize(hmac_shared_secret, sizeof(hmac_shared_secret));
                pk_crypto_zeroize(decrypted_salts, sizeof(decrypted_salts));
            }
            return up_res;
        }
        up_flag = true;
    }

    ctap2_notify_processing(ctap);

    /* Increment signature counter */
    uint32_t sign_cnt = 0;
    if (pk_storage_next_sign_counter(ctap->storage, &sign_cnt) != PK_OK) {
        if (ext_hmac_secret_requested) {
            pk_crypto_zeroize(hmac_shared_secret, sizeof(hmac_shared_secret));
            pk_crypto_zeroize(decrypted_salts, sizeof(decrypted_salts));
        }
        return CTAP2_ERR_PROCESSING;
    }

    ctap2_notify_processing(ctap);

    /* Compute hmac-secret output if requested and enabled on chosen credential */
    uint8_t hmac_enc_out[64];
    size_t hmac_enc_out_len = 0;
    bool include_hmac_secret_in_authdata = false;

    if (ext_hmac_secret_requested && ctap->assertion_session.creds[0].hmac_secret_enabled) {
        pk_err_t herr = compute_hmac_secret_output(
            ctap,
            &ctap->assertion_session.creds[0],
            hmac_shared_secret,
            decrypted_salts,
            decrypted_salts_len,
            hmac_enc_out,
            &hmac_enc_out_len
        );
        if (herr == PK_OK) {
            include_hmac_secret_in_authdata = true;
        }
    }

    /* Build authData (37 bytes base + extension data map if hmac-secret included) */
    uint8_t auth_data[128];
    memcpy(&auth_data[0], rp_id_hash, 32);
    uint8_t flags = 0;
    if (up_flag) {
        flags |= CTAP2_AUTH_DATA_FLAG_UP;
    }
    if (uv_flag) {
        flags |= CTAP2_AUTH_DATA_FLAG_UV;
    }
    if (include_hmac_secret_in_authdata) {
        flags |= CTAP2_AUTH_DATA_FLAG_ED;
    }
    auth_data[32] = flags;
    auth_data[33] = (uint8_t)(sign_cnt >> 24);
    auth_data[34] = (uint8_t)(sign_cnt >> 16);
    auth_data[35] = (uint8_t)(sign_cnt >> 8);
    auth_data[36] = (uint8_t)(sign_cnt);
    size_t auth_data_len = 37;

    if (include_hmac_secret_in_authdata) {
        pk_cbor_writer_t ext_w;
        pk_cbor_writer_init(&ext_w, auth_data + 37, sizeof(auth_data) - 37);
        pk_cbor_encode_map_header(&ext_w, 1);
        pk_cbor_encode_tstr_c(&ext_w, "hmac-secret");
        pk_cbor_encode_bstr(&ext_w, hmac_enc_out, hmac_enc_out_len);
        if (ext_w.err != PK_OK) {
            if (ext_hmac_secret_requested) {
                pk_crypto_zeroize(hmac_shared_secret, sizeof(hmac_shared_secret));
                pk_crypto_zeroize(decrypted_salts, sizeof(decrypted_salts));
            }
            return CTAP2_ERR_PROCESSING;
        }
        auth_data_len += ext_w.offset;
    }

    /* Cache chosen credential */
    pk_resident_cred_t chosen_cred = ctap->assertion_session.creds[0];

    /* Sign authData || clientDataHash */
    uint8_t sig_hash[32];
    pk_crypto_sha256_two(auth_data, auth_data_len, client_data_hash, 32, sig_hash);

    uint8_t sig_der[PK_ECDSA_MAX_DER_SIG_LEN];
    size_t sig_der_len = 0;
    if (pk_crypto_p256_sign_der(ctap->crypto, chosen_cred.priv_key, sig_hash, sig_der, &sig_der_len) != PK_OK) {
        pk_crypto_zeroize(&chosen_cred, sizeof(chosen_cred));
        if (ext_hmac_secret_requested) {
            pk_crypto_zeroize(hmac_shared_secret, sizeof(hmac_shared_secret));
            pk_crypto_zeroize(decrypted_salts, sizeof(decrypted_salts));
        }
        return CTAP2_ERR_PROCESSING;
    }
    ctap2_notify_processing(ctap);

    /* Cache multi-assertion session state if match_count > 1 */
    if (match_count > 1) {
        ctap->assertion_session.active = true;
        ctap->assertion_session.created_ms = ctap->platform->now_ms(ctap->platform->ctx);
        ctap->assertion_session.total_creds = match_count;
        ctap->assertion_session.next_index = 1;
        ctap->assertion_session.flags = auth_data[32];
        memcpy(ctap->assertion_session.rp_id_hash, rp_id_hash, 32);
        memcpy(ctap->assertion_session.client_data_hash, client_data_hash, 32);
        ctap->assertion_session.hmac_secret_requested = ext_hmac_secret_requested;
        if (ext_hmac_secret_requested) {
            memcpy(ctap->assertion_session.hmac_shared_secret, hmac_shared_secret, 32);
            memcpy(ctap->assertion_session.hmac_salts, decrypted_salts, decrypted_salts_len);
            ctap->assertion_session.hmac_salts_len = decrypted_salts_len;
        }
    } else {
        /* Single assertion: zeroize session state */
        clear_assertion_session(ctap);
    }

    if (ext_hmac_secret_requested) {
        pk_crypto_zeroize(hmac_shared_secret, sizeof(hmac_shared_secret));
        pk_crypto_zeroize(decrypted_salts, sizeof(decrypted_salts));
    }

    /* Encode response */
    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, resp + 1, max_resp_len - 1);
    pk_err_t enc_err = encode_assertion_response(&w, &chosen_cred, auth_data, auth_data_len, sig_der, sig_der_len, match_count);
    pk_crypto_zeroize(&chosen_cred, sizeof(chosen_cred));

    if (enc_err != PK_OK) {
        return (w.err == PK_ERR_BUFFER_TOO_SMALL) ? CTAP2_ERR_LIMIT_EXCEEDED : CTAP2_ERR_PROCESSING;
    }

    resp[0] = CTAP2_OK;
    *out_resp_len = 1 + w.offset;
    return CTAP2_OK;
}

/* CTAP2_CMD_GET_NEXT_ASSERTION (0x08) */
static uint8_t handle_get_next_assertion(
    pk_ctap2_ctx_t *ctap,
    size_t cbor_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
) {
    if (cbor_len != 0) {
        return CTAP1_ERR_INVALID_LENGTH;
    }

    if (!ctap->assertion_session.active ||
        ctap->assertion_session.next_index >= ctap->assertion_session.total_creds) {
        clear_assertion_session(ctap);
        return CTAP2_ERR_NOT_ALLOWED;
    }

    uint64_t now_ms = ctap->platform->now_ms(ctap->platform->ctx);
    if (now_ms - ctap->assertion_session.created_ms > PK_MULTI_ASSERTION_TIMEOUT_MS) {
        clear_assertion_session(ctap);
        return CTAP2_ERR_NOT_ALLOWED;
    }

    pk_resident_cred_t *cred = &ctap->assertion_session.creds[ctap->assertion_session.next_index++];

    uint32_t sign_cnt = 0;
    if (pk_storage_next_sign_counter(ctap->storage, &sign_cnt) != PK_OK) {
        return CTAP2_ERR_PROCESSING;
    }
    ctap2_notify_processing(ctap);

    /* Compute hmac-secret output if requested and enabled on this credential */
    uint8_t hmac_enc_out[64];
    size_t hmac_enc_out_len = 0;
    bool include_hmac_secret = false;

    if (ctap->assertion_session.hmac_secret_requested && cred->hmac_secret_enabled) {
        pk_err_t herr = compute_hmac_secret_output(
            ctap,
            cred,
            ctap->assertion_session.hmac_shared_secret,
            ctap->assertion_session.hmac_salts,
            ctap->assertion_session.hmac_salts_len,
            hmac_enc_out,
            &hmac_enc_out_len
        );
        if (herr == PK_OK) {
            include_hmac_secret = true;
        }
    }

    uint8_t auth_data[128];
    memcpy(&auth_data[0], ctap->assertion_session.rp_id_hash, 32);
    uint8_t flags = ctap->assertion_session.flags;
    if (include_hmac_secret) {
        flags |= CTAP2_AUTH_DATA_FLAG_ED;
    } else {
        flags &= ~CTAP2_AUTH_DATA_FLAG_ED;
    }
    auth_data[32] = flags;
    auth_data[33] = (uint8_t)(sign_cnt >> 24);
    auth_data[34] = (uint8_t)(sign_cnt >> 16);
    auth_data[35] = (uint8_t)(sign_cnt >> 8);
    auth_data[36] = (uint8_t)(sign_cnt);
    size_t auth_data_len = 37;

    if (include_hmac_secret) {
        pk_cbor_writer_t ext_w;
        pk_cbor_writer_init(&ext_w, auth_data + 37, sizeof(auth_data) - 37);
        pk_cbor_encode_map_header(&ext_w, 1);
        pk_cbor_encode_tstr_c(&ext_w, "hmac-secret");
        pk_cbor_encode_bstr(&ext_w, hmac_enc_out, hmac_enc_out_len);
        if (ext_w.err != PK_OK) {
            return CTAP2_ERR_PROCESSING;
        }
        auth_data_len += ext_w.offset;
    }

    uint8_t sig_hash[32];
    pk_crypto_sha256_two(auth_data, auth_data_len, ctap->assertion_session.client_data_hash, 32, sig_hash);

    uint8_t sig_der[PK_ECDSA_MAX_DER_SIG_LEN];
    size_t sig_der_len = 0;
    if (pk_crypto_p256_sign_der(ctap->crypto, cred->priv_key, sig_hash, sig_der, &sig_der_len) != PK_OK) {
        return CTAP2_ERR_PROCESSING;
    }
    ctap2_notify_processing(ctap);

    pk_resident_cred_t chosen_cred = *cred;

    if (ctap->assertion_session.next_index >= ctap->assertion_session.total_creds) {
        clear_assertion_session(ctap);
    }

    pk_cbor_writer_t w;
    pk_cbor_writer_init(&w, resp + 1, max_resp_len - 1);
    pk_err_t enc_err = encode_assertion_response(&w, &chosen_cred, auth_data, auth_data_len, sig_der, sig_der_len, 0);
    pk_crypto_zeroize(&chosen_cred, sizeof(chosen_cred));

    if (enc_err != PK_OK) {
        return (w.err == PK_ERR_BUFFER_TOO_SMALL) ? CTAP2_ERR_LIMIT_EXCEEDED : CTAP2_ERR_PROCESSING;
    }

    resp[0] = CTAP2_OK;
    *out_resp_len = 1 + w.offset;
    return CTAP2_OK;
}

/* CTAP2_CMD_CLIENT_PIN (0x06) */
static uint8_t handle_client_pin(
    pk_ctap2_ctx_t *ctap,
    const uint8_t *cbor_buf,
    size_t cbor_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
) {
    ctap2_notify_processing(ctap);
    size_t cbor_out_len = 0;
    uint8_t status = pk_pin_handle_command(
        ctap->pin,
        cbor_buf,
        cbor_len,
        resp + 1,
        max_resp_len - 1,
        &cbor_out_len
    );
    ctap2_notify_processing(ctap);
    resp[0] = status;
    *out_resp_len = 1 + cbor_out_len;
    return status;
}

/* CTAP2_CMD_RESET (0x07) */
static uint8_t handle_reset(
    pk_ctap2_ctx_t *ctap,
    size_t cbor_len,
    uint8_t *resp,
    size_t *out_resp_len
) {
    if (cbor_len != 0) {
        return CTAP1_ERR_INVALID_LENGTH;
    }

    uint64_t now_ms = ctap->platform->now_ms(ctap->platform->ctx);
    if (now_ms > PK_RESET_WINDOW_MS) {
        return CTAP2_ERR_NOT_ALLOWED;
    }

    uint8_t up_res = ctap2_request_up(ctap);
    if (up_res != CTAP2_OK) {
        return up_res;
    }

    ctap2_notify_processing(ctap);
    pk_storage_factory_reset(ctap->storage);
    pk_pin_reset(ctap->pin);
    clear_assertion_session(ctap);
    memset(&ctap->cred_mgmt_session, 0, sizeof(ctap->cred_mgmt_session));
    ctap2_notify_processing(ctap);

    resp[0] = CTAP2_OK;
    *out_resp_len = 1;
    return CTAP2_OK;
}

/* CTAP2_CMD_SELECTION (0x0B) */
static uint8_t handle_selection(
    pk_ctap2_ctx_t *ctap,
    uint8_t *resp,
    size_t *out_resp_len
) {
    uint8_t up_res = ctap2_request_up(ctap);
    if (up_res != CTAP2_OK) {
        return up_res;
    }
    resp[0] = CTAP2_OK;
    *out_resp_len = 1;
    return CTAP2_OK;
}

/* CTAP2_CMD_CREDENTIAL_MGMT (0x0A) and CTAP2_CMD_CREDENTIAL_MGMT_PRE (0x41) */
static uint8_t handle_credential_mgmt(
    pk_ctap2_ctx_t *ctap,
    const uint8_t *cbor_buf,
    size_t cbor_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
) {
    if (cbor_len == 0) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    pk_cbor_reader_t r;
    pk_cbor_reader_init(&r, cbor_buf, cbor_len);

    size_t map_count = 0;
    if (pk_cbor_decode_map_header(&r, &map_count) != PK_OK) {
        return CTAP2_ERR_INVALID_CBOR;
    }

    uint64_t subcmd = 0;
    bool subcmd_present = false;

    const uint8_t *sub_params_raw = NULL;
    size_t sub_params_raw_len = 0;

    uint64_t pin_proto = 0;
    bool pin_proto_present = false;

    const uint8_t *pin_auth = NULL;
    size_t pin_auth_len = 0;
    bool pin_auth_present = false;

    for (size_t i = 0; i < map_count; i++) {
        uint64_t key = 0;
        if (pk_cbor_decode_uint(&r, &key) != PK_OK) {
            return CTAP2_ERR_INVALID_CBOR;
        }
        switch (key) {
            case 0x01: { /* subCommand */
                if (pk_cbor_decode_uint(&r, &subcmd) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                subcmd_present = true;
                break;
            }
            case 0x02: { /* subCommandParams */
                sub_params_raw = r.buf + r.offset;
                if (pk_cbor_skip_item(&r) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                sub_params_raw_len = (size_t)((r.buf + r.offset) - sub_params_raw);
                break;
            }
            case 0x03: { /* pinUvAuthProtocol */
                if (pk_cbor_decode_uint(&r, &pin_proto) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                pin_proto_present = true;
                break;
            }
            case 0x04: { /* pinUvAuthParam */
                if (pk_cbor_decode_bstr(&r, &pin_auth, &pin_auth_len) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                pin_auth_present = true;
                break;
            }
            default: {
                if (pk_cbor_skip_item(&r) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                break;
            }
        }
    }

    if (!subcmd_present) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    /* Subcommands 0x03 and 0x05 are getNext, so they don't require pinAuth if session is already active */
    if (subcmd != 0x03 && subcmd != 0x05) {
        if (!pin_auth_present || pin_auth_len == 0) {
            return CTAP2_ERR_PIN_REQUIRED;
        }
        if (!pin_proto_present || pin_proto != 1) {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
    }

    switch (subcmd) {
        case 0x01: { /* getCredsMetadata */
            uint8_t sub_byte = 0x01;
            uint8_t pin_err = verify_cred_mgmt_auth(ctap->pin, (uint8_t)pin_proto, &sub_byte, 1, pin_auth, pin_auth_len);
            if (pin_err != CTAP2_OK) {
                return pin_err;
            }

            size_t active_creds = 0;
            size_t free_creds = 0;
            size_t rp_count = 0;
            pk_storage_get_stats(ctap->storage, &active_creds, &free_creds, &rp_count);

            pk_cbor_writer_t w;
            pk_cbor_writer_init(&w, resp + 1, max_resp_len - 1);
            pk_cbor_encode_map_header(&w, 2);
            pk_cbor_encode_uint(&w, 0x01);
            pk_cbor_encode_uint(&w, active_creds);
            pk_cbor_encode_uint(&w, 0x02);
            pk_cbor_encode_uint(&w, free_creds);

            if (w.err != PK_OK) {
                return (w.err == PK_ERR_BUFFER_TOO_SMALL) ? CTAP2_ERR_LIMIT_EXCEEDED : CTAP2_ERR_PROCESSING;
            }
            resp[0] = CTAP2_OK;
            *out_resp_len = 1 + w.offset;
            return CTAP2_OK;
        }

        case 0x02: { /* enumerateRPsBegin */
            uint8_t sub_byte = 0x02;
            uint8_t pin_err = verify_cred_mgmt_auth(ctap->pin, (uint8_t)pin_proto, &sub_byte, 1, pin_auth, pin_auth_len);
            if (pin_err != CTAP2_OK) {
                return pin_err;
            }

            pk_rp_summary_t rps[PK_STORAGE_MAX_RESIDENT_CREDS];
            size_t total_rps = 0;
            pk_storage_list_rps(ctap->storage, rps, PK_STORAGE_MAX_RESIDENT_CREDS, &total_rps);
            if (total_rps == 0) {
                return CTAP2_ERR_NO_CREDENTIALS;
            }

            ctap->cred_mgmt_session.rp_enum_active = true;
            ctap->cred_mgmt_session.rp_enum_created_ms = ctap->platform->now_ms(ctap->platform->ctx);
            ctap->cred_mgmt_session.total_rps = total_rps;
            ctap->cred_mgmt_session.next_rp_index = 1;

            pk_cbor_writer_t w;
            pk_cbor_writer_init(&w, resp + 1, max_resp_len - 1);
            pk_cbor_encode_map_header(&w, 3);

            /* 0x03: rPEntity */
            pk_cbor_encode_uint(&w, 0x03);
            pk_cbor_encode_map_header(&w, 1);
            pk_cbor_encode_tstr_c(&w, "id");
            pk_cbor_encode_tstr_c(&w, rps[0].rp_id);

            /* 0x04: rpIdHash */
            pk_cbor_encode_uint(&w, 0x04);
            pk_cbor_encode_bstr(&w, rps[0].rp_id_hash, 32);

            /* 0x05: totalRPs */
            pk_cbor_encode_uint(&w, 0x05);
            pk_cbor_encode_uint(&w, total_rps);

            if (w.err != PK_OK) {
                return (w.err == PK_ERR_BUFFER_TOO_SMALL) ? CTAP2_ERR_LIMIT_EXCEEDED : CTAP2_ERR_PROCESSING;
            }
            resp[0] = CTAP2_OK;
            *out_resp_len = 1 + w.offset;
            return CTAP2_OK;
        }

        case 0x03: { /* enumerateRPsGetNextRP */
            if (!ctap->cred_mgmt_session.rp_enum_active ||
                ctap->cred_mgmt_session.next_rp_index >= ctap->cred_mgmt_session.total_rps) {
                ctap->cred_mgmt_session.rp_enum_active = false;
                return CTAP2_ERR_NO_CREDENTIALS;
            }

            uint64_t now_ms = ctap->platform->now_ms(ctap->platform->ctx);
            if (now_ms - ctap->cred_mgmt_session.rp_enum_created_ms > PK_MULTI_ASSERTION_TIMEOUT_MS) {
                ctap->cred_mgmt_session.rp_enum_active = false;
                return CTAP2_ERR_NOT_ALLOWED;
            }

            pk_rp_summary_t rps[PK_STORAGE_MAX_RESIDENT_CREDS];
            size_t total_rps = 0;
            pk_storage_list_rps(ctap->storage, rps, PK_STORAGE_MAX_RESIDENT_CREDS, &total_rps);
            size_t idx = ctap->cred_mgmt_session.next_rp_index++;

            if (idx >= total_rps) {
                ctap->cred_mgmt_session.rp_enum_active = false;
                return CTAP2_ERR_NO_CREDENTIALS;
            }

            pk_cbor_writer_t w;
            pk_cbor_writer_init(&w, resp + 1, max_resp_len - 1);
            pk_cbor_encode_map_header(&w, 2);

            /* 0x03: rPEntity */
            pk_cbor_encode_uint(&w, 0x03);
            pk_cbor_encode_map_header(&w, 1);
            pk_cbor_encode_tstr_c(&w, "id");
            pk_cbor_encode_tstr_c(&w, rps[idx].rp_id);

            /* 0x04: rpIdHash */
            pk_cbor_encode_uint(&w, 0x04);
            pk_cbor_encode_bstr(&w, rps[idx].rp_id_hash, 32);

            if (w.err != PK_OK) {
                return (w.err == PK_ERR_BUFFER_TOO_SMALL) ? CTAP2_ERR_LIMIT_EXCEEDED : CTAP2_ERR_PROCESSING;
            }
            resp[0] = CTAP2_OK;
            *out_resp_len = 1 + w.offset;
            return CTAP2_OK;
        }

        case 0x04: { /* enumerateCredentialsBegin */
            if (!sub_params_raw || sub_params_raw_len == 0) {
                return CTAP2_ERR_MISSING_PARAMETER;
            }

            pk_cbor_reader_t sub_r;
            pk_cbor_reader_init(&sub_r, sub_params_raw, sub_params_raw_len);
            size_t sub_map_count = 0;
            if (pk_cbor_decode_map_header(&sub_r, &sub_map_count) != PK_OK) {
                return CTAP2_ERR_INVALID_CBOR;
            }

            const uint8_t *rp_id_hash_param = NULL;
            size_t rp_id_hash_param_len = 0;

            for (size_t j = 0; j < sub_map_count; j++) {
                uint64_t skey = 0;
                if (pk_cbor_decode_uint(&sub_r, &skey) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                if (skey == 0x01) {
                    if (pk_cbor_decode_bstr(&sub_r, &rp_id_hash_param, &rp_id_hash_param_len) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                } else {
                    if (pk_cbor_skip_item(&sub_r) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                }
            }

            if (!rp_id_hash_param || rp_id_hash_param_len != 32) {
                return CTAP2_ERR_MISSING_PARAMETER;
            }

            uint8_t mac_buf[1 + 256];
            if (sub_params_raw_len > 256) {
                return CTAP2_ERR_LIMIT_EXCEEDED;
            }
            mac_buf[0] = 0x04;
            memcpy(mac_buf + 1, sub_params_raw, sub_params_raw_len);

            uint8_t pin_err = verify_cred_mgmt_auth(ctap->pin, (uint8_t)pin_proto, mac_buf, 1 + sub_params_raw_len, pin_auth, pin_auth_len);
            if (pin_err != CTAP2_OK) {
                return pin_err;
            }

            pk_resident_cred_t creds[PK_STORAGE_MAX_RESIDENT_CREDS];
            size_t total_creds = 0;
            pk_storage_find_by_rp(ctap->storage, rp_id_hash_param, creds, PK_STORAGE_MAX_RESIDENT_CREDS, &total_creds);
            if (total_creds == 0) {
                return CTAP2_ERR_NO_CREDENTIALS;
            }

            ctap->cred_mgmt_session.cred_enum_active = true;
            ctap->cred_mgmt_session.cred_enum_created_ms = ctap->platform->now_ms(ctap->platform->ctx);
            memcpy(ctap->cred_mgmt_session.cred_enum_rp_id_hash, rp_id_hash_param, 32);
            ctap->cred_mgmt_session.total_creds = total_creds;
            ctap->cred_mgmt_session.next_cred_index = 1;

            pk_cbor_writer_t w;
            pk_cbor_writer_init(&w, resp + 1, max_resp_len - 1);
            pk_cbor_encode_map_header(&w, 5);

            /* 0x06: user */
            size_t u_count = 1;
            if (creds[0].user_name[0] != '\0') u_count++;
            if (creds[0].user_display_name[0] != '\0') u_count++;

            pk_cbor_encode_uint(&w, 0x06);
            pk_cbor_encode_map_header(&w, u_count);
            pk_cbor_encode_tstr_c(&w, "id");
            pk_cbor_encode_bstr(&w, creds[0].user_id, creds[0].user_id_len);
            if (creds[0].user_name[0] != '\0') {
                pk_cbor_encode_tstr_c(&w, "name");
                pk_cbor_encode_tstr_c(&w, creds[0].user_name);
            }
            if (creds[0].user_display_name[0] != '\0') {
                pk_cbor_encode_tstr_c(&w, "displayName");
                pk_cbor_encode_tstr_c(&w, creds[0].user_display_name);
            }

            /* 0x07: credentialId */
            pk_cbor_encode_uint(&w, 0x07);
            pk_cbor_encode_map_header(&w, 2);
            pk_cbor_encode_tstr_c(&w, "id");
            pk_cbor_encode_bstr(&w, creds[0].cred_id, sizeof(creds[0].cred_id));
            pk_cbor_encode_tstr_c(&w, "type");
            pk_cbor_encode_tstr_c(&w, "public-key");

            /* 0x08: publicKey */
            pk_cbor_encode_uint(&w, 0x08);
            pk_cbor_encode_cose_p256_pubkey(&w, &creds[0].pub_key, false);

            /* 0x09: totalCredentials */
            pk_cbor_encode_uint(&w, 0x09);
            pk_cbor_encode_uint(&w, total_creds);

            /* 0x0A: credProtect */
            pk_cbor_encode_uint(&w, 0x0A);
            pk_cbor_encode_uint(&w, creds[0].cred_Provide_up_uv_flags > 0 ? creds[0].cred_Provide_up_uv_flags : 1U);

            for (size_t c = 0; c < total_creds; c++) {
                pk_crypto_zeroize(&creds[c], sizeof(creds[c]));
            }

            if (w.err != PK_OK) {
                return (w.err == PK_ERR_BUFFER_TOO_SMALL) ? CTAP2_ERR_LIMIT_EXCEEDED : CTAP2_ERR_PROCESSING;
            }
            resp[0] = CTAP2_OK;
            *out_resp_len = 1 + w.offset;
            return CTAP2_OK;
        }

        case 0x05: { /* enumerateCredentialsGetNextCredential */
            if (!ctap->cred_mgmt_session.cred_enum_active ||
                ctap->cred_mgmt_session.next_cred_index >= ctap->cred_mgmt_session.total_creds) {
                ctap->cred_mgmt_session.cred_enum_active = false;
                return CTAP2_ERR_NO_CREDENTIALS;
            }

            uint64_t now_ms = ctap->platform->now_ms(ctap->platform->ctx);
            if (now_ms - ctap->cred_mgmt_session.cred_enum_created_ms > PK_MULTI_ASSERTION_TIMEOUT_MS) {
                ctap->cred_mgmt_session.cred_enum_active = false;
                return CTAP2_ERR_NOT_ALLOWED;
            }

            pk_resident_cred_t creds[PK_STORAGE_MAX_RESIDENT_CREDS];
            size_t total_creds = 0;
            pk_storage_find_by_rp(ctap->storage, ctap->cred_mgmt_session.cred_enum_rp_id_hash, creds, PK_STORAGE_MAX_RESIDENT_CREDS, &total_creds);
            size_t idx = ctap->cred_mgmt_session.next_cred_index++;

            if (idx >= total_creds) {
                ctap->cred_mgmt_session.cred_enum_active = false;
                for (size_t c = 0; c < total_creds; c++) {
                    pk_crypto_zeroize(&creds[c], sizeof(creds[c]));
                }
                return CTAP2_ERR_NO_CREDENTIALS;
            }

            pk_cbor_writer_t w;
            pk_cbor_writer_init(&w, resp + 1, max_resp_len - 1);
            pk_cbor_encode_map_header(&w, 4);

            /* 0x06: user */
            size_t u_count = 1;
            if (creds[idx].user_name[0] != '\0') u_count++;
            if (creds[idx].user_display_name[0] != '\0') u_count++;

            pk_cbor_encode_uint(&w, 0x06);
            pk_cbor_encode_map_header(&w, u_count);
            pk_cbor_encode_tstr_c(&w, "id");
            pk_cbor_encode_bstr(&w, creds[idx].user_id, creds[idx].user_id_len);
            if (creds[idx].user_name[0] != '\0') {
                pk_cbor_encode_tstr_c(&w, "name");
                pk_cbor_encode_tstr_c(&w, creds[idx].user_name);
            }
            if (creds[idx].user_display_name[0] != '\0') {
                pk_cbor_encode_tstr_c(&w, "displayName");
                pk_cbor_encode_tstr_c(&w, creds[idx].user_display_name);
            }

            /* 0x07: credentialId */
            pk_cbor_encode_uint(&w, 0x07);
            pk_cbor_encode_map_header(&w, 2);
            pk_cbor_encode_tstr_c(&w, "id");
            pk_cbor_encode_bstr(&w, creds[idx].cred_id, sizeof(creds[idx].cred_id));
            pk_cbor_encode_tstr_c(&w, "type");
            pk_cbor_encode_tstr_c(&w, "public-key");

            /* 0x08: publicKey */
            pk_cbor_encode_uint(&w, 0x08);
            pk_cbor_encode_cose_p256_pubkey(&w, &creds[idx].pub_key, false);

            /* 0x0A: credProtect */
            pk_cbor_encode_uint(&w, 0x0A);
            pk_cbor_encode_uint(&w, creds[idx].cred_Provide_up_uv_flags > 0 ? creds[idx].cred_Provide_up_uv_flags : 1U);

            for (size_t c = 0; c < total_creds; c++) {
                pk_crypto_zeroize(&creds[c], sizeof(creds[c]));
            }

            if (w.err != PK_OK) {
                return (w.err == PK_ERR_BUFFER_TOO_SMALL) ? CTAP2_ERR_LIMIT_EXCEEDED : CTAP2_ERR_PROCESSING;
            }
            resp[0] = CTAP2_OK;
            *out_resp_len = 1 + w.offset;
            return CTAP2_OK;
        }

        case 0x06: { /* deleteCredential */
            if (!sub_params_raw || sub_params_raw_len == 0) {
                return CTAP2_ERR_MISSING_PARAMETER;
            }

            pk_cbor_reader_t sub_r;
            pk_cbor_reader_init(&sub_r, sub_params_raw, sub_params_raw_len);
            size_t sub_map_count = 0;
            if (pk_cbor_decode_map_header(&sub_r, &sub_map_count) != PK_OK) {
                return CTAP2_ERR_INVALID_CBOR;
            }

            const uint8_t *target_cid = NULL;
            size_t target_cid_len = 0;

            for (size_t j = 0; j < sub_map_count; j++) {
                uint64_t skey = 0;
                if (pk_cbor_decode_uint(&sub_r, &skey) != PK_OK) {
                    return CTAP2_ERR_INVALID_CBOR;
                }
                if (skey == 0x02) {
                    /* PublicKeyCredentialDescriptor */
                    size_t desc_count = 0;
                    if (pk_cbor_decode_map_header(&sub_r, &desc_count) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                    for (size_t k = 0; k < desc_count; k++) {
                        const char *dk = NULL;
                        size_t dk_len = 0;
                        if (pk_cbor_decode_tstr(&sub_r, &dk, &dk_len) != PK_OK) {
                            return CTAP2_ERR_INVALID_CBOR;
                        }
                        if (dk_len == 2 && memcmp(dk, "id", 2) == 0) {
                            if (pk_cbor_decode_bstr(&sub_r, &target_cid, &target_cid_len) != PK_OK) {
                                return CTAP2_ERR_INVALID_CBOR;
                            }
                        } else {
                            if (pk_cbor_skip_item(&sub_r) != PK_OK) {
                                return CTAP2_ERR_INVALID_CBOR;
                            }
                        }
                    }
                } else {
                    if (pk_cbor_skip_item(&sub_r) != PK_OK) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                }
            }

            if (!target_cid || target_cid_len == 0) {
                return CTAP2_ERR_MISSING_PARAMETER;
            }

            uint8_t mac_buf[1 + 256];
            if (sub_params_raw_len > 256) {
                return CTAP2_ERR_LIMIT_EXCEEDED;
            }
            mac_buf[0] = 0x06;
            memcpy(mac_buf + 1, sub_params_raw, sub_params_raw_len);

            uint8_t pin_err = verify_cred_mgmt_auth(ctap->pin, (uint8_t)pin_proto, mac_buf, 1 + sub_params_raw_len, pin_auth, pin_auth_len);
            if (pin_err != CTAP2_OK) {
                return pin_err;
            }

            pk_err_t del_err = pk_storage_delete_by_id(ctap->storage, target_cid, target_cid_len);
            if (del_err == PK_ERR_NOT_FOUND) {
                return CTAP2_ERR_NO_CREDENTIALS;
            } else if (del_err != PK_OK) {
                return CTAP2_ERR_PROCESSING;
            }

            resp[0] = CTAP2_OK;
            *out_resp_len = 1;
            return CTAP2_OK;
        }

        default:
            return CTAP2_ERR_INVALID_SUBCOMMAND;
    }
}

/* Process a raw CTAP2 CBOR command message */
void pk_ctap2_process_message(
    pk_ctap2_ctx_t *ctap,
    const uint8_t *req,
    size_t req_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
) {
    if (!req || req_len == 0 || !resp || max_resp_len < 1) {
        if (resp && max_resp_len >= 1) {
            resp[0] = CTAP1_ERR_INVALID_LENGTH;
            if (out_resp_len) {
                *out_resp_len = 1;
            }
        }
        return;
    }

    if (!out_resp_len) {
        return;
    }

    if (!ctap) {
        resp[0] = CTAP1_ERR_OTHER;
        *out_resp_len = 1;
        return;
    }

    uint8_t cmd = req[0];
    const uint8_t *cbor_buf = req + 1;
    size_t cbor_len = req_len - 1;

    /* Any command other than GET_NEXT_ASSERTION clears assertion session */
    if (cmd != CTAP2_CMD_GET_NEXT_ASSERTION) {
        clear_assertion_session(ctap);
    }

    /* Any command other than CREDENTIAL_MGMT clears credential management enumeration session */
    if (cmd != CTAP2_CMD_CREDENTIAL_MGMT && cmd != CTAP2_CMD_CREDENTIAL_MGMT_PRE) {
        memset(&ctap->cred_mgmt_session, 0, sizeof(ctap->cred_mgmt_session));
    }

    /* Default fallback length */
    *out_resp_len = 1;

    uint8_t status = CTAP1_ERR_INVALID_COMMAND;

    switch (cmd) {
        case CTAP2_CMD_GET_INFO:
            status = handle_get_info(ctap, cbor_len, resp, max_resp_len, out_resp_len);
            break;
        case CTAP2_CMD_MAKE_CREDENTIAL:
            status = handle_make_credential(ctap, cbor_buf, cbor_len, resp, max_resp_len, out_resp_len);
            break;
        case CTAP2_CMD_GET_ASSERTION:
            status = handle_get_assertion(ctap, cbor_buf, cbor_len, resp, max_resp_len, out_resp_len);
            break;
        case CTAP2_CMD_GET_NEXT_ASSERTION:
            status = handle_get_next_assertion(ctap, cbor_len, resp, max_resp_len, out_resp_len);
            break;
        case CTAP2_CMD_CLIENT_PIN:
            status = handle_client_pin(ctap, cbor_buf, cbor_len, resp, max_resp_len, out_resp_len);
            break;
        case CTAP2_CMD_RESET:
            status = handle_reset(ctap, cbor_len, resp, out_resp_len);
            break;
        case CTAP2_CMD_SELECTION:
            status = handle_selection(ctap, resp, out_resp_len);
            break;
        case CTAP2_CMD_CREDENTIAL_MGMT:
        case CTAP2_CMD_CREDENTIAL_MGMT_PRE:
            status = handle_credential_mgmt(ctap, cbor_buf, cbor_len, resp, max_resp_len, out_resp_len);
            break;
        default:
            status = CTAP1_ERR_INVALID_COMMAND;
            break;
    }

    if (status != CTAP2_OK) {
        resp[0] = status;
        *out_resp_len = 1;
    }
}

/* Process a Legacy U2F / CTAP1 raw APDU */
void pk_ctap1_process_apdu(
    pk_ctap2_ctx_t *ctap,
    const uint8_t *apdu,
    size_t apdu_len,
    uint8_t *resp,
    size_t max_resp_len,
    size_t *out_resp_len
) {
    if (!resp || max_resp_len < 2 || !out_resp_len) {
        if (out_resp_len) {
            *out_resp_len = 0;
        }
        return;
    }

    if (!apdu || apdu_len < 4) {
        resp[0] = 0x67; /* SW_WRONG_LENGTH */
        resp[1] = 0x00;
        *out_resp_len = 2;
        return;
    }

    if (apdu[0] != 0x00) {
        resp[0] = 0x6E; /* SW_CLA_NOT_SUPPORTED */
        resp[1] = 0x00;
        *out_resp_len = 2;
        return;
    }

    uint8_t ins = apdu[1];
    uint8_t p1 = apdu[2];

    /* Parse Short or Extended ISO 7816-4 APDU data field */
    const uint8_t *data = NULL;
    size_t lc = 0;
    if (apdu_len > 4) {
        if (apdu[4] == 0x00 && apdu_len >= 7) {
            size_t ext_lc = ((size_t)apdu[5] << 8) | (size_t)apdu[6];
            if (ext_lc > 0 && 7 + ext_lc <= apdu_len) {
                lc = ext_lc;
                data = &apdu[7];
            }
        } else {
            size_t short_lc = apdu[4];
            if (5 + short_lc <= apdu_len) {
                lc = short_lc;
                data = &apdu[5];
            }
        }
    }

    if (ins == 0x03) {
        /* U2F_VERSION -> "U2F_V2" + 0x90 0x00 (8 bytes) */
        if (lc != 0 || max_resp_len < 8) {
            resp[0] = 0x67;
            resp[1] = 0x00;
            *out_resp_len = 2;
            return;
        }
        memcpy(resp, "U2F_V2", 6);
        resp[6] = 0x90;
        resp[7] = 0x00;
        *out_resp_len = 8;
        return;
    }

    if (!ctap || !ctap->crypto || !ctap->storage) {
        resp[0] = 0x6F;
        resp[1] = 0x00;
        *out_resp_len = 2;
        return;
    }

    if (ins == 0x01) {
        /* U2F_REGISTER: data = challenge_param(32) || app_param(32) */
        if (lc != 64 || !data) {
            resp[0] = 0x67;
            resp[1] = 0x00;
            *out_resp_len = 2;
            return;
        }

        if (ctap2_request_up(ctap) != CTAP2_OK) {
            resp[0] = 0x69; /* SW_CONDITIONS_NOT_SATISFIED */
            resp[1] = 0x85;
            *out_resp_len = 2;
            return;
        }

        const uint8_t *challenge_param = &data[0];
        const uint8_t *app_param = &data[32];

        uint8_t key_handle[PK_CRED_ID_NONRESIDENT_LEN];
        uint8_t cred_random[32];
        uint8_t priv_key[PK_P256_PRIVKEY_LEN];
        pk_p256_pubkey_t pub_key;

        if (pk_crypto_seal_nonresident_cred_id(ctap->crypto, ctap->storage->state.cred_mac_key, app_param, key_handle, cred_random) != PK_OK ||
            pk_crypto_derive_credential_keypair(ctap->storage->state.master_secret, app_param, cred_random, priv_key, &pub_key) != PK_OK) {
            pk_crypto_zeroize(cred_random, sizeof(cred_random));
            pk_crypto_zeroize(priv_key, sizeof(priv_key));
            resp[0] = 0x6F;
            resp[1] = 0x00;
            *out_resp_len = 2;
            return;
        }
        pk_crypto_zeroize(cred_random, sizeof(cred_random));
        pk_crypto_zeroize(priv_key, sizeof(priv_key));
        ctap2_notify_processing(ctap);

        uint8_t att_priv[PK_P256_PRIVKEY_LEN];
        uint8_t cert_der[600];
        size_t cert_der_len = 0;
        if (pk_crypto_build_attestation_cert_der(ctap->crypto, ctap->storage->state.attestation_seed, att_priv, cert_der, sizeof(cert_der), &cert_der_len) != PK_OK) {
            resp[0] = 0x6F;
            resp[1] = 0x00;
            *out_resp_len = 2;
            return;
        }
        ctap2_notify_processing(ctap);

        /* Signature over: 0x00 (1B) || app_param (32B) || challenge_param (32B) || key_handle (64B) || 0x04 || pub_key.x (32B) || pub_key.y (32B) */
        uint8_t sig_input[1 + 32 + 32 + 64 + 65];
        sig_input[0] = 0x00;
        memcpy(&sig_input[1], app_param, 32);
        memcpy(&sig_input[33], challenge_param, 32);
        memcpy(&sig_input[65], key_handle, 64);
        sig_input[129] = 0x04;
        memcpy(&sig_input[130], pub_key.x, 32);
        memcpy(&sig_input[162], pub_key.y, 32);

        uint8_t sig_hash[32];
        pk_crypto_sha256(sig_input, sizeof(sig_input), sig_hash);

        uint8_t sig_der[PK_ECDSA_MAX_DER_SIG_LEN];
        size_t sig_der_len = 0;
        pk_err_t s_err = pk_crypto_p256_sign_der(ctap->crypto, att_priv, sig_hash, sig_der, &sig_der_len);
        pk_crypto_zeroize(att_priv, sizeof(att_priv));
        ctap2_notify_processing(ctap);
        if (s_err != PK_OK) {
            resp[0] = 0x6F;
            resp[1] = 0x00;
            *out_resp_len = 2;
            return;
        }

        size_t total_len = 1 + 65 + 1 + 64 + cert_der_len + sig_der_len + 2;
        if (max_resp_len < total_len) {
            resp[0] = 0x67;
            resp[1] = 0x00;
            *out_resp_len = 2;
            return;
        }

        size_t pos = 0;
        resp[pos++] = 0x05;
        resp[pos++] = 0x04;
        memcpy(&resp[pos], pub_key.x, 32);
        pos += 32;
        memcpy(&resp[pos], pub_key.y, 32);
        pos += 32;
        resp[pos++] = 64;
        memcpy(&resp[pos], key_handle, 64);
        pos += 64;
        memcpy(&resp[pos], cert_der, cert_der_len);
        pos += cert_der_len;
        memcpy(&resp[pos], sig_der, sig_der_len);
        pos += sig_der_len;
        resp[pos++] = 0x90;
        resp[pos++] = 0x00;
        *out_resp_len = pos;
        return;
    }

    if (ins == 0x02) {
        /* U2F_AUTHENTICATE: data = challenge_param(32) || app_param(32) || kh_len(1) || kh(kh_len) */
        if (lc < 65 || !data) {
            resp[0] = 0x67;
            resp[1] = 0x00;
            *out_resp_len = 2;
            return;
        }

        const uint8_t *challenge_param = &data[0];
        const uint8_t *app_param = &data[32];
        uint8_t kh_len = data[64];
        if (lc < (size_t)(65 + kh_len)) {
            resp[0] = 0x67;
            resp[1] = 0x00;
            *out_resp_len = 2;
            return;
        }
        const uint8_t *kh = &data[65];

        uint8_t cred_random[32];
        if (kh_len != PK_CRED_ID_NONRESIDENT_LEN ||
            pk_crypto_unseal_nonresident_cred_id(ctap->storage->state.cred_mac_key, app_param, kh, cred_random) != PK_OK) {
            resp[0] = 0x6A; /* SW_WRONG_DATA */
            resp[1] = 0x80;
            *out_resp_len = 2;
            return;
        }

        /* P1 == 0x07: check-only -> return 0x6985 to indicate valid key handle */
        if (p1 == 0x07) {
            pk_crypto_zeroize(cred_random, sizeof(cred_random));
            resp[0] = 0x69;
            resp[1] = 0x85;
            *out_resp_len = 2;
            return;
        }

        if (p1 != 0x03 && p1 != 0x08) {
            pk_crypto_zeroize(cred_random, sizeof(cred_random));
            resp[0] = 0x6A; /* SW_INCORRECT_P1P2 */
            resp[1] = 0x86;
            *out_resp_len = 2;
            return;
        }

        if (p1 == 0x03) {
            if (ctap2_request_up(ctap) != CTAP2_OK) {
                pk_crypto_zeroize(cred_random, sizeof(cred_random));
                resp[0] = 0x69;
                resp[1] = 0x85;
                *out_resp_len = 2;
                return;
            }
        }

        uint8_t priv_key[PK_P256_PRIVKEY_LEN];
        pk_p256_pubkey_t pub_key;
        if (pk_crypto_derive_credential_keypair(ctap->storage->state.master_secret, app_param, cred_random, priv_key, &pub_key) != PK_OK) {
            pk_crypto_zeroize(cred_random, sizeof(cred_random));
            resp[0] = 0x6F;
            resp[1] = 0x00;
            *out_resp_len = 2;
            return;
        }
        pk_crypto_zeroize(cred_random, sizeof(cred_random));
        ctap2_notify_processing(ctap);

        uint32_t sign_cnt = 0;
        if (pk_storage_next_sign_counter(ctap->storage, &sign_cnt) != PK_OK) {
            pk_crypto_zeroize(priv_key, sizeof(priv_key));
            resp[0] = 0x6F;
            resp[1] = 0x00;
            *out_resp_len = 2;
            return;
        }

        uint8_t sig_input[32 + 1 + 4 + 32];
        memcpy(&sig_input[0], app_param, 32);
        sig_input[32] = 0x01;
        sig_input[33] = (uint8_t)(sign_cnt >> 24);
        sig_input[34] = (uint8_t)(sign_cnt >> 16);
        sig_input[35] = (uint8_t)(sign_cnt >> 8);
        sig_input[36] = (uint8_t)(sign_cnt);
        memcpy(&sig_input[37], challenge_param, 32);

        uint8_t sig_hash[32];
        pk_crypto_sha256(sig_input, sizeof(sig_input), sig_hash);

        uint8_t sig_der[PK_ECDSA_MAX_DER_SIG_LEN];
        size_t sig_der_len = 0;
        pk_err_t s_err = pk_crypto_p256_sign_der(ctap->crypto, priv_key, sig_hash, sig_der, &sig_der_len);
        pk_crypto_zeroize(priv_key, sizeof(priv_key));
        ctap2_notify_processing(ctap);
        if (s_err != PK_OK || max_resp_len < (1 + 4 + sig_der_len + 2)) {
            resp[0] = 0x6F;
            resp[1] = 0x00;
            *out_resp_len = 2;
            return;
        }

        resp[0] = 0x01;
        resp[1] = (uint8_t)(sign_cnt >> 24);
        resp[2] = (uint8_t)(sign_cnt >> 16);
        resp[3] = (uint8_t)(sign_cnt >> 8);
        resp[4] = (uint8_t)(sign_cnt);
        memcpy(&resp[5], sig_der, sig_der_len);
        resp[5 + sig_der_len] = 0x90;
        resp[6 + sig_der_len] = 0x00;
        *out_resp_len = 7 + sig_der_len;
        return;
    }

    /* Unsupported INS -> 0x6D00 (INS_NOT_SUPPORTED) */
    resp[0] = 0x6D;
    resp[1] = 0x00;
    *out_resp_len = 2;
}
