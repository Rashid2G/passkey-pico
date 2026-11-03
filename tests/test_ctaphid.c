#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "passkey/ctaphid.h"
#include "passkey/usb_hid.h"
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

#define MAX_CAPTURED_PACKETS 32

typedef struct {
    uint8_t packets[MAX_CAPTURED_PACKETS][PK_HID_PACKET_SIZE];
    size_t count;
} tx_capture_t;

static void mock_tx_cb(void *tx_ctx, const uint8_t packet[PK_HID_PACKET_SIZE])
{
    tx_capture_t *cap = (tx_capture_t *)tx_ctx;
    if (cap->count < MAX_CAPTURED_PACKETS) {
        memcpy(cap->packets[cap->count], packet, PK_HID_PACKET_SIZE);
        cap->count++;
    }
}

static void tx_capture_clear(tx_capture_t *cap)
{
    memset(cap, 0, sizeof(*cap));
}

static inline void encode_u32_be(uint8_t *dst, uint32_t val)
{
    dst[0] = (uint8_t)(val >> 24);
    dst[1] = (uint8_t)(val >> 16);
    dst[2] = (uint8_t)(val >> 8);
    dst[3] = (uint8_t)(val);
}

static inline uint32_t decode_u32_be(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  |
           ((uint32_t)src[3]);
}

static inline uint16_t decode_u16_be(const uint8_t *src)
{
    return (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
}

static void send_init_frame(
    pk_ctaphid_ctx_t *hid,
    uint32_t cid,
    uint8_t cmd,
    uint16_t total_payload_len,
    const uint8_t *chunk_data,
    size_t chunk_len
) {
    uint8_t pkt[PK_HID_PACKET_SIZE];
    memset(pkt, 0, sizeof(pkt));

    encode_u32_be(&pkt[0], cid);
    pkt[4] = cmd | CTAPHID_TYPE_INIT;
    pkt[5] = (uint8_t)(total_payload_len >> 8);
    pkt[6] = (uint8_t)(total_payload_len & 0xFF);

    if (chunk_data && chunk_len > 0) {
        size_t to_copy = (chunk_len > 57) ? 57 : chunk_len;
        memcpy(&pkt[7], chunk_data, to_copy);
    }

    pk_ctaphid_rx_packet(hid, pkt);
}

static void send_cont_frame(
    pk_ctaphid_ctx_t *hid,
    uint32_t cid,
    uint8_t seq,
    const uint8_t *chunk_data,
    size_t chunk_len
) {
    uint8_t pkt[PK_HID_PACKET_SIZE];
    memset(pkt, 0, sizeof(pkt));

    encode_u32_be(&pkt[0], cid);
    pkt[4] = seq & 0x7FU;

    if (chunk_data && chunk_len > 0) {
        size_t to_copy = (chunk_len > 59) ? 59 : chunk_len;
        memcpy(&pkt[5], chunk_data, to_copy);
    }

    pk_ctaphid_rx_packet(hid, pkt);
}

/* Helper to reassemble multi-packet response */
static int reassemble_response(
    const tx_capture_t *cap,
    uint32_t *out_cid,
    uint8_t *out_cmd,
    uint8_t *out_payload,
    size_t max_payload_len,
    size_t *out_payload_len
) {
    if (!cap || cap->count == 0) {
        return -1;
    }

    const uint8_t *first = cap->packets[0];
    *out_cid = decode_u32_be(&first[0]);
    *out_cmd = first[4];
    uint16_t total_len = decode_u16_be(&first[5]);
    *out_payload_len = total_len;

    if (total_len > max_payload_len) {
        return -2;
    }

    size_t copied = 0;
    size_t init_chunk = (total_len > 57) ? 57 : total_len;
    memcpy(out_payload, &first[7], init_chunk);
    copied += init_chunk;

    size_t expected_packets = 1;
    if (total_len > 57) {
        expected_packets += (total_len - 57 + 58) / 59;
    }

    if (cap->count != expected_packets) {
        return -3;
    }

    for (size_t p = 1; p < cap->count && copied < total_len; p++) {
        const uint8_t *cont = cap->packets[p];
        uint32_t cont_cid = decode_u32_be(&cont[0]);
        if (cont_cid != *out_cid) return -4;
        uint8_t seq = cont[4];
        if (seq != (uint8_t)(p - 1)) return -5;

        size_t remaining = total_len - copied;
        size_t cont_chunk = (remaining > 59) ? 59 : remaining;
        memcpy(out_payload + copied, &cont[5], cont_chunk);
        copied += cont_chunk;
    }

    return 0;
}

/* Helper: perform CTAPHID_CMD_INIT on broadcast CID and return newly allocated CID */
static int helper_allocate_cid(
    pk_ctaphid_ctx_t *hid,
    tx_capture_t *cap,
    const uint8_t nonce[8],
    uint32_t *out_allocated_cid
) {
    tx_capture_clear(cap);
    send_init_frame(hid, CTAPHID_BROADCAST_CID, CTAPHID_CMD_INIT, 8, nonce, 8);

    if (cap->count != 1) return -1;
    const uint8_t *resp = cap->packets[0];

    uint32_t resp_cid = decode_u32_be(&resp[0]);
    if (resp_cid != CTAPHID_BROADCAST_CID) return -2;

    uint8_t cmd = resp[4];
    if (cmd != CTAPHID_CMD_INIT) return -3;

    uint16_t bcnt = decode_u16_be(&resp[5]);
    if (bcnt != 17) return -4;

    /* Verify echoed nonce */
    if (memcmp(&resp[7], nonce, 8) != 0) return -5;

    /* Allocated CID */
    uint32_t alloc_cid = decode_u32_be(&resp[15]);
    if (alloc_cid == 0 || alloc_cid == CTAPHID_BROADCAST_CID) return -6;

    *out_allocated_cid = alloc_cid;
    return 0;
}

/* 1. Verify pk_fido_hid_report_desc */
static int test_report_descriptor(void)
{
    TEST_ASSERT(PK_FIDO_HID_REPORT_DESC_LEN == 34U, "Report descriptor length must be exactly 34 bytes");
    TEST_ASSERT(pk_fido_hid_report_desc[0] == 0x06, "Byte 0 must be 0x06 (Usage Page)");
    TEST_ASSERT(pk_fido_hid_report_desc[1] == 0xD0, "Byte 1 must be 0xD0 (FIDO Alliance)");
    TEST_ASSERT(pk_fido_hid_report_desc[2] == 0xF1, "Byte 2 must be 0xF1 (FIDO Alliance)");
    TEST_ASSERT(pk_fido_hid_report_desc[33] == 0xC0, "Last byte must be 0xC0 (End Collection)");

    TEST_PASS_MSG("FIDO USB HID Report Descriptor (34 bytes, starts with 0x06, 0xD0, 0xF1)");
    return 0;
}

/* 2. Test CTAPHID_CMD_INIT on broadcast CID */
static int test_cmd_init_broadcast(pk_ctaphid_ctx_t *hid, tx_capture_t *cap)
{
    static const uint8_t nonce[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    uint32_t allocated_cid = 0;

    int res = helper_allocate_cid(hid, cap, nonce, &allocated_cid);
    TEST_ASSERT(res == 0, "helper_allocate_cid failed");
    TEST_ASSERT(allocated_cid != 0 && allocated_cid != CTAPHID_BROADCAST_CID,
                "Allocated CID must be non-zero and non-broadcast");

    const uint8_t *resp = cap->packets[0];
    /* Protocol version (byte 12 of payload = resp[19]) */
    uint8_t proto_ver = resp[19];
    TEST_ASSERT(proto_ver == 2, "Protocol version must be 2");

    /* Firmware version */
    TEST_ASSERT(resp[20] == PK_FIRMWARE_VERSION_MAJOR, "Major version mismatch");
    TEST_ASSERT(resp[21] == PK_FIRMWARE_VERSION_MINOR, "Minor version mismatch");
    TEST_ASSERT(resp[22] == PK_FIRMWARE_VERSION_BUILD, "Build version mismatch");

    /* Capability flags: WINK (0x01) and CBOR (0x04) */
    uint8_t caps = resp[23];
    TEST_ASSERT((caps & CTAPHID_CAPABILITY_WINK) != 0, "Capability WINK must be set");
    TEST_ASSERT((caps & CTAPHID_CAPABILITY_CBOR) != 0, "Capability CBOR must be set");

    TEST_PASS_MSG("CTAPHID_CMD_INIT on broadcast CID 0xFFFFFFFF (17B payload, nonce, caps)");
    return 0;
}

/* 3. Test CTAPHID_CMD_PING with single-packet and multi-packet payloads */
static int test_cmd_ping_single_and_multi(pk_ctaphid_ctx_t *hid, tx_capture_t *cap)
{
    static const uint8_t nonce[8] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };
    uint32_t cid = 0;
    int res = helper_allocate_cid(hid, cap, nonce, &cid);
    TEST_ASSERT(res == 0, "Channel allocation for PING test failed");

    /* A. Single-packet PING (20 bytes) */
    static const uint8_t ping20[] = "0123456789abcdefghij";
    tx_capture_clear(cap);

    send_init_frame(hid, cid, CTAPHID_CMD_PING, 20, ping20, 20);
    TEST_ASSERT(cap->count == 1, "Single-packet PING response must be 1 frame");

    uint32_t resp_cid = 0;
    uint8_t resp_cmd = 0;
    uint8_t resp_payload[512];
    size_t resp_len = 0;

    res = reassemble_response(cap, &resp_cid, &resp_cmd, resp_payload, sizeof(resp_payload), &resp_len);
    TEST_ASSERT(res == 0, "Failed to reassemble single-packet PING response");
    TEST_ASSERT(resp_cid == cid, "Response CID mismatch");
    TEST_ASSERT(resp_cmd == CTAPHID_CMD_PING, "Response command must be CTAPHID_CMD_PING");
    TEST_ASSERT(resp_len == 20, "Response payload length must be 20");
    TEST_ASSERT(memcmp(resp_payload, ping20, 20) == 0, "PING payload mismatch");

    /* B. Multi-packet PING (300 bytes payload across INIT + 5 CONT frames) */
    uint8_t ping300[300];
    for (size_t i = 0; i < sizeof(ping300); ++i) {
        ping300[i] = (uint8_t)((i * 13 + 7) & 0xFF);
    }

    tx_capture_clear(cap);

    /* Frame 0 (INIT): 57 bytes */
    send_init_frame(hid, cid, CTAPHID_CMD_PING, 300, &ping300[0], 57);
    TEST_ASSERT(cap->count == 0, "Response should not be sent before all frames arrive");

    /* Frame 1..5 (CONT seq 0..4): 59, 59, 59, 59, 7 bytes */
    size_t sent = 57;
    for (uint8_t seq = 0; seq < 5; seq++) {
        size_t remaining = 300 - sent;
        size_t chunk = (remaining > 59) ? 59 : remaining;
        send_cont_frame(hid, cid, seq, &ping300[sent], chunk);
        sent += chunk;
    }
    TEST_ASSERT(sent == 300, "Should have sent all 300 bytes");

    /* Response should now have been generated: 300 bytes = 1 INIT (57B) + 5 CONT (59+59+59+59+7) = 6 packets */
    TEST_ASSERT(cap->count == 6, "Multi-packet response must comprise exactly 6 packets");

    res = reassemble_response(cap, &resp_cid, &resp_cmd, resp_payload, sizeof(resp_payload), &resp_len);
    TEST_ASSERT(res == 0, "Failed to reassemble 300-byte PING response");
    TEST_ASSERT(resp_cid == cid, "Response CID mismatch");
    TEST_ASSERT(resp_cmd == CTAPHID_CMD_PING, "Response command mismatch");
    TEST_ASSERT(resp_len == 300, "Response length must be 300");
    TEST_ASSERT(memcmp(resp_payload, ping300, 300) == 0, "Reassembled 300-byte payload mismatch");

    TEST_PASS_MSG("CTAPHID_CMD_PING single-packet and 300-byte multi-packet reassembly & segmentation");
    return 0;
}

/* 4. Test sequence error handling: out-of-order CONT frame */
static int test_sequence_error_handling(pk_ctaphid_ctx_t *hid, tx_capture_t *cap)
{
    static const uint8_t nonce[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    uint32_t cid = 0;
    helper_allocate_cid(hid, cap, nonce, &cid);

    tx_capture_clear(cap);

    /* Start multi-packet message with bcnt = 120 */
    uint8_t dummy[120];
    memset(dummy, 0x55, sizeof(dummy));
    send_init_frame(hid, cid, CTAPHID_CMD_PING, 120, dummy, 57);

    /* Send out-of-order CONT frame: expected seq is 0, send seq 1 */
    send_cont_frame(hid, cid, 1, &dummy[57], 59);

    /* Should immediately emit CTAPHID_CMD_ERROR (0xBF) with CTAP1_ERR_INVALID_SEQ (0x04) */
    TEST_ASSERT(cap->count == 1, "Must emit error frame on sequence error");
    const uint8_t *err_pkt = cap->packets[0];
    TEST_ASSERT(decode_u32_be(&err_pkt[0]) == cid, "Error CID mismatch");
    TEST_ASSERT(err_pkt[4] == CTAPHID_CMD_ERROR, "Packet must be CTAPHID_CMD_ERROR");
    TEST_ASSERT(decode_u16_be(&err_pkt[5]) == 1, "Error length must be 1");
    TEST_ASSERT(err_pkt[7] == CTAP1_ERR_INVALID_SEQ, "Error code must be CTAP1_ERR_INVALID_SEQ (0x04)");

    TEST_PASS_MSG("Sequence error handling (out-of-order CONT returns CTAP1_ERR_INVALID_SEQ)");
    return 0;
}

/* 5. Test transaction timeout: start multi-packet message, advance mock clock by 600ms */
static int test_transaction_timeout(
    pk_mock_platform_state_t *mock,
    pk_ctaphid_ctx_t *hid,
    tx_capture_t *cap
) {
    static const uint8_t nonce[8] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    uint32_t cid = 0;
    helper_allocate_cid(hid, cap, nonce, &cid);

    tx_capture_clear(cap);

    /* Start multi-packet message (bcnt = 200) */
    uint8_t dummy[57];
    memset(dummy, 0x33, sizeof(dummy));
    send_init_frame(hid, cid, CTAPHID_CMD_PING, 200, dummy, 57);
    TEST_ASSERT(cap->count == 0, "No response yet");

    /* Advance clock by 600ms (exceeding PK_CTAPHID_TRANS_TIMEOUT_MS = 500ms) */
    pk_mock_platform_advance_time(mock, 600);

    /* Call periodic timeout checker */
    pk_ctaphid_check_timeouts(hid);

    /* Must respond with CTAPHID_CMD_ERROR and CTAP1_ERR_TIMEOUT (0x05) */
    TEST_ASSERT(cap->count == 1, "Must emit timeout error packet");
    const uint8_t *err_pkt = cap->packets[0];
    TEST_ASSERT(decode_u32_be(&err_pkt[0]) == cid, "Error CID mismatch");
    TEST_ASSERT(err_pkt[4] == CTAPHID_CMD_ERROR, "Command must be CTAPHID_CMD_ERROR");
    TEST_ASSERT(err_pkt[7] == CTAP1_ERR_TIMEOUT, "Error code must be CTAP1_ERR_TIMEOUT (0x05)");

    TEST_PASS_MSG("Transaction timeout (500ms expiry returns CTAP1_ERR_TIMEOUT 0x05)");
    return 0;
}

/* 6. Test invalid channel handling: CID == 0, non-INIT on 0xFFFFFFFF, unallocated CID */
static int test_invalid_channel_handling(pk_ctaphid_ctx_t *hid, tx_capture_t *cap)
{
    /* A. CID == 0 -> CTAP1_ERR_INVALID_CHANNEL */
    tx_capture_clear(cap);
    send_init_frame(hid, 0x00000000UL, CTAPHID_CMD_PING, 8, (const uint8_t *)"testping", 8);
    TEST_ASSERT(cap->count == 1, "Must emit error for CID 0");
    TEST_ASSERT(cap->packets[0][4] == CTAPHID_CMD_ERROR, "Must be error frame");
    TEST_ASSERT(cap->packets[0][7] == CTAP1_ERR_INVALID_CHANNEL, "Must return CTAP1_ERR_INVALID_CHANNEL (0x0B)");

    /* B. Non-INIT on broadcast CID 0xFFFFFFFF -> CTAP1_ERR_INVALID_CHANNEL */
    tx_capture_clear(cap);
    send_init_frame(hid, CTAPHID_BROADCAST_CID, CTAPHID_CMD_PING, 8, (const uint8_t *)"testping", 8);
    TEST_ASSERT(cap->count == 1, "Must emit error for non-INIT broadcast command");
    TEST_ASSERT(cap->packets[0][4] == CTAPHID_CMD_ERROR, "Must be error frame");
    TEST_ASSERT(cap->packets[0][7] == CTAP1_ERR_INVALID_CHANNEL, "Must return CTAP1_ERR_INVALID_CHANNEL (0x0B)");

    /* C. Non-broadcast CID that was never allocated -> CTAP1_ERR_INVALID_CHANNEL */
    tx_capture_clear(cap);
    send_init_frame(hid, 0x12345678UL, CTAPHID_CMD_PING, 8, (const uint8_t *)"testping", 8);
    TEST_ASSERT(cap->count == 1, "Must emit error for unallocated CID");
    TEST_ASSERT(cap->packets[0][4] == CTAPHID_CMD_ERROR, "Must be error frame");
    TEST_ASSERT(cap->packets[0][7] == CTAP1_ERR_INVALID_CHANNEL, "Must return CTAP1_ERR_INVALID_CHANNEL (0x0B)");

    TEST_PASS_MSG("Invalid channel handling (CID 0, non-INIT broadcast, and unallocated CID)");
    return 0;
}

/* 7. Test channel busy & CTAPHID_CMD_LOCK across two channels */
static int test_channel_lock_and_busy(pk_ctaphid_ctx_t *hid, tx_capture_t *cap)
{
    static const uint8_t nonce1[8] = { 1, 1, 1, 1, 1, 1, 1, 1 };
    static const uint8_t nonce2[8] = { 2, 2, 2, 2, 2, 2, 2, 2 };

    uint32_t cid1 = 0;
    uint32_t cid2 = 0;

    int res = helper_allocate_cid(hid, cap, nonce1, &cid1);
    TEST_ASSERT(res == 0, "Channel 1 allocation failed");

    res = helper_allocate_cid(hid, cap, nonce2, &cid2);
    TEST_ASSERT(res == 0, "Channel 2 allocation failed");
    TEST_ASSERT(cid1 != cid2, "Allocated CIDs must be distinct");

    /* Lock Channel 1 for 5 seconds */
    tx_capture_clear(cap);
    uint8_t lock_duration = 5;
    send_init_frame(hid, cid1, CTAPHID_CMD_LOCK, 1, &lock_duration, 1);
    TEST_ASSERT(cap->count == 1, "LOCK response must be 1 frame");
    TEST_ASSERT(cap->packets[0][4] == CTAPHID_CMD_LOCK, "Response must be CTAPHID_CMD_LOCK");
    TEST_ASSERT(decode_u16_be(&cap->packets[0][5]) == 0, "LOCK response payload len must be 0");

    /* Channel 2 sends PING while Channel 1 holds the lock -> CTAP1_ERR_CHANNEL_BUSY (0x06) */
    tx_capture_clear(cap);
    send_init_frame(hid, cid2, CTAPHID_CMD_PING, 4, (const uint8_t *)"ping", 4);
    TEST_ASSERT(cap->count == 1, "Channel 2 should receive error frame");
    TEST_ASSERT(cap->packets[0][4] == CTAPHID_CMD_ERROR, "Must be error frame");
    TEST_ASSERT(cap->packets[0][7] == CTAP1_ERR_CHANNEL_BUSY, "Must return CTAP1_ERR_CHANNEL_BUSY (0x06)");

    /* Channel 1 sends PING -> succeeds */
    tx_capture_clear(cap);
    send_init_frame(hid, cid1, CTAPHID_CMD_PING, 4, (const uint8_t *)"ping", 4);
    TEST_ASSERT(cap->count == 1, "Channel 1 PING should succeed");
    TEST_ASSERT(cap->packets[0][4] == CTAPHID_CMD_PING, "Must be PING response");

    /* Unlock Channel 1 (seconds = 0) */
    tx_capture_clear(cap);
    lock_duration = 0;
    send_init_frame(hid, cid1, CTAPHID_CMD_LOCK, 1, &lock_duration, 1);
    TEST_ASSERT(cap->count == 1, "UNLOCK response must be 1 frame");
    TEST_ASSERT(cap->packets[0][4] == CTAPHID_CMD_LOCK, "Response must be CTAPHID_CMD_LOCK");

    /* Now Channel 2 sends PING -> succeeds */
    tx_capture_clear(cap);
    send_init_frame(hid, cid2, CTAPHID_CMD_PING, 4, (const uint8_t *)"ping", 4);
    TEST_ASSERT(cap->count == 1, "Channel 2 PING should now succeed");
    TEST_ASSERT(cap->packets[0][4] == CTAPHID_CMD_PING, "Must be PING response");

    /* Test concurrent multi-packet busy rejection:
     * Channel 1 begins a multi-packet message (bcnt = 200).
     * Channel 2 sends a packet before Channel 1 finishes -> Channel 2 gets CTAP1_ERR_CHANNEL_BUSY.
     */
    tx_capture_clear(cap);
    uint8_t payload[57];
    memset(payload, 0x77, sizeof(payload));
    send_init_frame(hid, cid1, CTAPHID_CMD_PING, 200, payload, 57);

    /* Channel 2 tries to send */
    send_init_frame(hid, cid2, CTAPHID_CMD_PING, 4, (const uint8_t *)"ping", 4);
    TEST_ASSERT(cap->count == 1, "Channel 2 must receive BUSY error");
    TEST_ASSERT(decode_u32_be(&cap->packets[0][0]) == cid2, "Error must be addressed to Channel 2");
    TEST_ASSERT(cap->packets[0][4] == CTAPHID_CMD_ERROR, "Must be error frame");
    TEST_ASSERT(cap->packets[0][7] == CTAP1_ERR_CHANNEL_BUSY, "Must return CTAP1_ERR_CHANNEL_BUSY (0x06)");

    /* Cancel in-progress message on Channel 1 so subsequent tests have a clean rx state */
    tx_capture_clear(cap);
    send_init_frame(hid, cid1, CTAPHID_CMD_CANCEL, 0, NULL, 0);

    TEST_PASS_MSG("Channel lock and busy rejection across multiple channels");
    return 0;
}

/* 8. Test CTAPHID_CMD_WINK increments mock.wink_count */
static int test_cmd_wink(
    pk_mock_platform_state_t *mock,
    pk_ctaphid_ctx_t *hid,
    tx_capture_t *cap
) {
    static const uint8_t nonce[8] = { 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC };
    uint32_t cid = 0;
    helper_allocate_cid(hid, cap, nonce, &cid);

    uint32_t winks_before = mock->wink_count;
    tx_capture_clear(cap);

    send_init_frame(hid, cid, CTAPHID_CMD_WINK, 0, NULL, 0);

    TEST_ASSERT(mock->wink_count == winks_before + 1, "Wink count must increment by 1");
    TEST_ASSERT(cap->count == 1, "WINK response must be 1 frame");
    TEST_ASSERT(cap->packets[0][4] == CTAPHID_CMD_WINK, "Response command must be CTAPHID_CMD_WINK");
    TEST_ASSERT(decode_u16_be(&cap->packets[0][5]) == 0, "WINK response payload length must be 0");

    TEST_PASS_MSG("CTAPHID_CMD_WINK (increments mock platform wink_count)");
    return 0;
}

int main(void)
{
    printf("=== Running CTAPHID transport unit tests ===\n");

    pk_mock_platform_state_t mock;
    pk_platform_t platform;
    pk_mock_platform_init(&mock, &platform);

    tx_capture_t cap;
    tx_capture_clear(&cap);

    pk_ctaphid_ctx_t hid;
    pk_err_t err = pk_ctaphid_init(&hid, &platform, NULL, mock_tx_cb, &cap);
    if (err != PK_OK) {
        fprintf(stderr, "pk_ctaphid_init failed: %d\n", (int)err);
        return 1;
    }

    if (test_report_descriptor() != 0) return 1;
    if (test_cmd_init_broadcast(&hid, &cap) != 0) return 1;
    if (test_cmd_ping_single_and_multi(&hid, &cap) != 0) return 1;
    if (test_sequence_error_handling(&hid, &cap) != 0) return 1;
    if (test_transaction_timeout(&mock, &hid, &cap) != 0) return 1;
    if (test_invalid_channel_handling(&hid, &cap) != 0) return 1;
    if (test_channel_lock_and_busy(&hid, &cap) != 0) return 1;
    if (test_cmd_wink(&mock, &hid, &cap) != 0) return 1;

    printf("\n[PASS] All CTAPHID transport unit tests passed successfully!\n");
    return 0;
}
