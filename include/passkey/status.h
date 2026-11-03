#ifndef PICO_PASSKEY_STATUS_H
#define PICO_PASSKEY_STATUS_H

#include <stdint.h>

/* Internal Module Error Codes */
typedef enum {
    PK_OK = 0,
    PK_ERR_INVALID_ARG,
    PK_ERR_BUFFER_TOO_SMALL,
    PK_ERR_OVERFLOW,
    PK_ERR_NOT_FOUND,
    PK_ERR_FULL,
    PK_ERR_CORRUPT,
    PK_ERR_CRYPTO,
    PK_ERR_AUTH_FAILED,
    PK_ERR_FLASH_IO,
    PK_ERR_TIMEOUT,
    PK_ERR_CANCELLED,
    PK_ERR_DENIED,
    PK_ERR_LOCKED,
    PK_ERR_STATE,
    PK_ERR_UNSUPPORTED
} pk_err_t;

/* Official FIDO CTAP1 / CTAP2 Status & Error Codes (FIDO CTAP v2.1 §6.3) */
#define CTAP1_ERR_SUCCESS                   0x00U
#define CTAP1_ERR_INVALID_COMMAND           0x01U
#define CTAP1_ERR_INVALID_PARAMETER         0x02U
#define CTAP1_ERR_INVALID_LENGTH            0x03U
#define CTAP1_ERR_INVALID_SEQ               0x04U
#define CTAP1_ERR_TIMEOUT                   0x05U
#define CTAP1_ERR_CHANNEL_BUSY              0x06U
#define CTAP1_ERR_LOCK_REQUIRED             0x0AU
#define CTAP1_ERR_INVALID_CHANNEL           0x0BU
#define CTAP1_ERR_OTHER                     0x7FU

#define CTAP2_OK                            0x00U
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE      0x11U
#define CTAP2_ERR_INVALID_CBOR              0x12U
#define CTAP2_ERR_MISSING_PARAMETER         0x14U
#define CTAP2_ERR_LIMIT_EXCEEDED            0x15U
#define CTAP2_ERR_FP_DATABASE_FULL          0x17U
#define CTAP2_ERR_LARGE_BLOB_STORAGE_FULL   0x18U
#define CTAP2_ERR_CREDENTIAL_EXCLUDED       0x19U
#define CTAP2_ERR_PROCESSING                0x21U
#define CTAP2_ERR_INVALID_CREDENTIAL        0x22U
#define CTAP2_ERR_USER_ACTION_PENDING       0x23U
#define CTAP2_ERR_OPERATION_PENDING         0x24U
#define CTAP2_ERR_NO_OPERATIONS             0x25U
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM     0x26U
#define CTAP2_ERR_OPERATION_DENIED          0x27U
#define CTAP2_ERR_KEY_STORE_FULL            0x28U
#define CTAP2_ERR_UNSUPPORTED_OPTION        0x2BU
#define CTAP2_ERR_INVALID_OPTION            0x2CU
#define CTAP2_ERR_KEEPALIVE_CANCEL          0x2DU
#define CTAP2_ERR_NO_CREDENTIALS            0x2EU
#define CTAP2_ERR_USER_ACTION_TIMEOUT       0x2FU
#define CTAP2_ERR_NOT_ALLOWED               0x30U
#define CTAP2_ERR_PIN_INVALID               0x31U
#define CTAP2_ERR_PIN_BLOCKED               0x32U
#define CTAP2_ERR_PIN_AUTH_INVALID          0x33U
#define CTAP2_ERR_PIN_AUTH_BLOCKED          0x34U
#define CTAP2_ERR_PIN_NOT_SET               0x35U
#define CTAP2_ERR_PIN_REQUIRED              0x36U
#define CTAP2_ERR_PIN_POLICY_VIOLATION      0x37U
#define CTAP2_ERR_PIN_TOKEN_EXPIRED         0x38U
#define CTAP2_ERR_REQUEST_TOO_LARGE         0x39U
#define CTAP2_ERR_ACTION_TIMEOUT            0x3AU
#define CTAP2_ERR_UP_REQUIRED               0x3BU
#define CTAP2_ERR_UV_BLOCKED                0x3CU
#define CTAP2_ERR_INTEGRITY_FAILURE         0x3DU
#define CTAP2_ERR_INVALID_SUBCOMMAND        0x3EU
#define CTAP2_ERR_UV_INVALID                0x3FU
#define CTAP2_ERR_UNAUTHORIZED_PERMISSION   0x40U

const char *pk_ctap_status_str(uint8_t status);

#endif /* PICO_PASSKEY_STATUS_H */
