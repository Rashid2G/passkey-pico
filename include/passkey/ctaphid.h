#ifndef PICO_PASSKEY_CTAPHID_H
#define PICO_PASSKEY_CTAPHID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "passkey/config.h"
#include "passkey/ctap2.h"
#include "passkey/platform.h"
#include "passkey/status.h"

/* CTAPHID Command Codes (with bit 7 set per FIDO CTAP v2.1 §11.2.9) */
#define CTAPHID_TYPE_INIT       0x80U
#define CTAPHID_CMD_MSG         (CTAPHID_TYPE_INIT | 0x03U) /* 0x83 */
#define CTAPHID_CMD_CBOR        (CTAPHID_TYPE_INIT | 0x10U) /* 0x90 */
#define CTAPHID_CMD_INIT        (CTAPHID_TYPE_INIT | 0x06U) /* 0x86 */
#define CTAPHID_CMD_PING        (CTAPHID_TYPE_INIT | 0x01U) /* 0x81 */
#define CTAPHID_CMD_CANCEL      (CTAPHID_TYPE_INIT | 0x11U) /* 0x91 */
#define CTAPHID_CMD_ERROR       (CTAPHID_TYPE_INIT | 0x3FU) /* 0xBF */
#define CTAPHID_CMD_KEEPALIVE   (CTAPHID_TYPE_INIT | 0x3BU) /* 0xBB */
#define CTAPHID_CMD_WINK        (CTAPHID_TYPE_INIT | 0x08U) /* 0x88 */
#define CTAPHID_CMD_LOCK        (CTAPHID_TYPE_INIT | 0x04U) /* 0x84 */

#define CTAPHID_BROADCAST_CID   0xFFFFFFFFUL

/* CTAPHID Capability Flags (§11.2.9.1.3) */
#define CTAPHID_CAPABILITY_WINK 0x01U
#define CTAPHID_CAPABILITY_CBOR 0x04U
#define CTAPHID_CAPABILITY_NMSG 0x08U

/* CTAPHID KEEPALIVE Status Codes (§11.2.9.2.2) */
#define CTAPHID_STATUS_PROCESSING 0x01U
#define CTAPHID_STATUS_UPNEEDED   0x02U

/* Callback for transmitting a single 64-byte HID IN report to the USB host */
typedef void (*pk_hid_tx_packet_cb_t)(void *tx_ctx, const uint8_t packet[PK_HID_PACKET_SIZE]);

typedef struct {
    bool     allocated;
    uint32_t cid;
    uint64_t last_active_ms;
} pk_ctaphid_channel_t;

typedef struct {
    bool     active;
    uint32_t cid;
    uint8_t  cmd;
    uint16_t total_len;
    uint16_t received_len;
    uint8_t  expected_seq;
    uint64_t start_ms;
    uint64_t last_packet_ms;
    uint8_t  payload[PK_CTAP2_MAX_MSG_SIZE];
} pk_ctaphid_rx_state_t;

typedef struct {
    const pk_platform_t   *platform;
    pk_ctap2_ctx_t        *ctap2;
    pk_hid_tx_packet_cb_t  tx_cb;
    void                  *tx_ctx;
    uint32_t               next_cid;
    pk_ctaphid_channel_t   channels[PK_CTAPHID_MAX_CHANNELS];
    pk_ctaphid_rx_state_t  rx;
    uint32_t               locked_cid;
    uint64_t               lock_until_ms;
    bool                   cancel_requested;
    uint32_t               active_cmd_cid;
    uint64_t               last_keepalive_ms;
    uint8_t                resp_buf[PK_CTAP2_MAX_MSG_SIZE];
} pk_ctaphid_ctx_t;

/* Initialize CTAPHID transport layer */
pk_err_t pk_ctaphid_init(
    pk_ctaphid_ctx_t *hid,
    const pk_platform_t *platform,
    pk_ctap2_ctx_t *ctap2,
    pk_hid_tx_packet_cb_t tx_cb,
    void *tx_ctx
);

/* Feed a received 64-byte USB HID report into the CTAPHID state machine */
void pk_ctaphid_rx_packet(
    pk_ctaphid_ctx_t *hid,
    const uint8_t packet[PK_HID_PACKET_SIZE]
);

/* Periodic tick handler: checks for incomplete multi-packet frame timeouts
 * (500ms per CTAP2 §11.2.9) and channel lock expiration.
 */
void pk_ctaphid_check_timeouts(pk_ctaphid_ctx_t *hid);

/* Send a complete response payload (`cmd`, `payload[0..len-1]`) segmented into one
 * INIT frame and zero or more CONT frames of 64 bytes each.
 */
void pk_ctaphid_send_response(
    pk_ctaphid_ctx_t *hid,
    uint32_t cid,
    uint8_t cmd,
    const uint8_t *payload,
    size_t len
);

/* Send a 1-byte CTAPHID_ERROR frame on `cid` */
void pk_ctaphid_send_error(pk_ctaphid_ctx_t *hid, uint32_t cid, uint8_t err_code);

#endif /* PICO_PASSKEY_CTAPHID_H */
