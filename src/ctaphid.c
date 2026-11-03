#include "passkey/ctaphid.h"
#include "passkey/usb_hid.h"
#include <string.h>

/* Helper functions for big-endian integer encoding / decoding */
static inline uint32_t decode_uint32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

static inline void encode_uint32_be(uint8_t *p, uint32_t val) {
    p[0] = (uint8_t)(val >> 24);
    p[1] = (uint8_t)(val >> 16);
    p[2] = (uint8_t)(val >> 8);
    p[3] = (uint8_t)(val);
}

static inline uint16_t decode_uint16_be(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline void encode_uint16_be(uint8_t *p, uint16_t val) {
    p[0] = (uint8_t)(val >> 8);
    p[1] = (uint8_t)(val);
}

/* Find the channel index matching `cid` in `hid->channels` */
static int find_channel_index(const pk_ctaphid_ctx_t *hid, uint32_t cid) {
    for (size_t i = 0; i < PK_CTAPHID_MAX_CHANNELS; i++) {
        if (hid->channels[i].allocated && hid->channels[i].cid == cid) {
            return (int)i;
        }
    }
    return -1;
}

/* Allocate a non-zero, non-broadcast CID that is not already in use */
static uint32_t allocate_next_cid(pk_ctaphid_ctx_t *hid) {
    for (;;) {
        uint32_t cid = hid->next_cid++;
        if (cid == 0 || cid == CTAPHID_BROADCAST_CID) {
            continue;
        }
        if (find_channel_index(hid, cid) < 0) {
            return cid;
        }
    }
}

/* Allocate a channel slot for a new CID (uses free slot or evicts LRU slot) */
static pk_ctaphid_channel_t *channel_allocate(pk_ctaphid_ctx_t *hid, uint64_t now_ms) {
    /* 1. Look for an unallocated slot */
    for (size_t i = 0; i < PK_CTAPHID_MAX_CHANNELS; i++) {
        if (!hid->channels[i].allocated) {
            hid->channels[i].allocated = true;
            hid->channels[i].cid = allocate_next_cid(hid);
            hid->channels[i].last_active_ms = now_ms;
            return &hid->channels[i];
        }
    }

    /* 2. All slots occupied: evict the least-recently-active slot */
    size_t lru_idx = 0;
    uint64_t min_active = hid->channels[0].last_active_ms;
    for (size_t i = 1; i < PK_CTAPHID_MAX_CHANNELS; i++) {
        if (hid->channels[i].last_active_ms < min_active) {
            min_active = hid->channels[i].last_active_ms;
            lru_idx = i;
        }
    }

    /* Clean up any lock or active reception belonging to the evicted channel */
    if (hid->locked_cid == hid->channels[lru_idx].cid) {
        hid->locked_cid = 0;
        hid->lock_until_ms = 0;
    }
    if (hid->rx.active && hid->rx.cid == hid->channels[lru_idx].cid) {
        hid->rx.active = false;
    }

    hid->channels[lru_idx].allocated = true;
    hid->channels[lru_idx].cid = allocate_next_cid(hid);
    hid->channels[lru_idx].last_active_ms = now_ms;
    return &hid->channels[lru_idx];
}

/* Keepalive callback invoked by CTAP2 layer while awaiting user presence or processing */
static bool ctaphid_keepalive_callback(void *user_ctx, uint8_t keepalive_status) {
    pk_ctaphid_ctx_t *hid = (pk_ctaphid_ctx_t *)user_ctx;
    if (!hid) {
        return false;
    }

    uint64_t now_ms = 0;
    if (hid->platform && hid->platform->now_ms) {
        now_ms = hid->platform->now_ms(hid->platform->ctx);
    }

    if (now_ms - hid->last_keepalive_ms >= PK_CTAPHID_KEEPALIVE_MS) {
        if (hid->active_cmd_cid != 0) {
            uint8_t status = keepalive_status;
            if (status == 0) {
                status = CTAPHID_STATUS_PROCESSING;
            }
            pk_ctaphid_send_response(hid, hid->active_cmd_cid, CTAPHID_CMD_KEEPALIVE, &status, 1);
        }
        hid->last_keepalive_ms = now_ms;
    }

#ifdef PICO_BUILD
    pk_usb_task();
#endif

    return hid->cancel_requested;
}

/* Dispatch an assembled CTAPHID command */
static void dispatch_command(pk_ctaphid_ctx_t *hid, uint32_t cid, uint64_t now_ms) {
    uint8_t cmd = hid->rx.cmd;
    uint16_t total_len = hid->rx.total_len;

    switch (cmd) {
    case CTAPHID_CMD_PING:
        pk_ctaphid_send_response(hid, cid, CTAPHID_CMD_PING, hid->rx.payload, total_len);
        break;

    case CTAPHID_CMD_WINK:
        if (hid->platform && hid->platform->wink) {
            hid->platform->wink(hid->platform->ctx);
        }
        pk_ctaphid_send_response(hid, cid, CTAPHID_CMD_WINK, NULL, 0);
        break;

    case CTAPHID_CMD_LOCK: {
        uint8_t seconds = hid->rx.payload[0];
        if (seconds > PK_CTAPHID_MAX_LOCK_SECONDS) {
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_PARAMETER);
            return;
        }
        if (seconds == 0) {
            hid->locked_cid = 0;
            hid->lock_until_ms = 0;
        } else {
            hid->locked_cid = cid;
            hid->lock_until_ms = now_ms + ((uint64_t)seconds * 1000ULL);
        }
        pk_ctaphid_send_response(hid, cid, CTAPHID_CMD_LOCK, NULL, 0);
        break;
    }

    case CTAPHID_CMD_CBOR: {
        hid->active_cmd_cid = cid;
        hid->cancel_requested = false;
        hid->last_keepalive_ms = now_ms;

        size_t resp_len = 0;
        if (hid->ctap2) {
            pk_ctap2_process_message(
                hid->ctap2,
                hid->rx.payload,
                total_len,
                hid->resp_buf,
                sizeof(hid->resp_buf),
                &resp_len
            );
        } else {
            hid->resp_buf[0] = CTAP1_ERR_OTHER;
            resp_len = 1;
        }

        pk_ctaphid_send_response(hid, cid, CTAPHID_CMD_CBOR, hid->resp_buf, resp_len);

        hid->active_cmd_cid = 0;
        hid->cancel_requested = false;
        break;
    }

    case CTAPHID_CMD_MSG: {
        hid->active_cmd_cid = cid;
        hid->cancel_requested = false;
        hid->last_keepalive_ms = now_ms;

        size_t resp_len = 0;
        if (hid->ctap2) {
            pk_ctap1_process_apdu(
                hid->ctap2,
                hid->rx.payload,
                total_len,
                hid->resp_buf,
                sizeof(hid->resp_buf),
                &resp_len
            );
        } else {
            hid->resp_buf[0] = 0x6FU;
            hid->resp_buf[1] = 0x00U;
            resp_len = 2;
        }

        pk_ctaphid_send_response(hid, cid, CTAPHID_CMD_MSG, hid->resp_buf, resp_len);

        hid->active_cmd_cid = 0;
        hid->cancel_requested = false;
        break;
    }

    default:
        pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_COMMAND);
        break;
    }
}

/* Initialize CTAPHID transport layer */
pk_err_t pk_ctaphid_init(
    pk_ctaphid_ctx_t *hid,
    const pk_platform_t *platform,
    pk_ctap2_ctx_t *ctap2,
    pk_hid_tx_packet_cb_t tx_cb,
    void *tx_ctx
) {
    if (!hid || !platform || !tx_cb) {
        return PK_ERR_INVALID_ARG;
    }

    memset(hid, 0, sizeof(*hid));
    hid->platform = platform;
    hid->ctap2 = ctap2;
    hid->tx_cb = tx_cb;
    hid->tx_ctx = tx_ctx;
    hid->next_cid = 0x00000001UL;

    if (ctap2 != NULL) {
        pk_ctap2_set_keepalive_callback(ctap2, ctaphid_keepalive_callback, hid);
    }

    return PK_OK;
}

/* Periodic tick handler */
void pk_ctaphid_check_timeouts(pk_ctaphid_ctx_t *hid) {
    if (!hid || !hid->platform || !hid->platform->now_ms) {
        return;
    }

    uint64_t now_ms = hid->platform->now_ms(hid->platform->ctx);

    /* Check lock expiration */
    if (hid->locked_cid != 0 && now_ms >= hid->lock_until_ms) {
        hid->locked_cid = 0;
        hid->lock_until_ms = 0;
    }

    /* Check multi-packet reassembly timeout (500ms) */
    if (hid->rx.active && (now_ms - hid->rx.last_packet_ms >= PK_CTAPHID_TRANS_TIMEOUT_MS)) {
        uint32_t timed_out_cid = hid->rx.cid;
        hid->rx.active = false;
        pk_ctaphid_send_error(hid, timed_out_cid, CTAP1_ERR_TIMEOUT);
    }
}

/* Feed a received 64-byte USB HID report into the CTAPHID state machine */
void pk_ctaphid_rx_packet(
    pk_ctaphid_ctx_t *hid,
    const uint8_t packet[PK_HID_PACKET_SIZE]
) {
    if (!hid || !packet) {
        return;
    }

    pk_ctaphid_check_timeouts(hid);

    uint64_t now_ms = 0;
    if (hid->platform && hid->platform->now_ms) {
        now_ms = hid->platform->now_ms(hid->platform->ctx);
    }

    uint32_t cid = decode_uint32_be(&packet[0]);
    uint8_t header = packet[4];

    if ((header & CTAPHID_TYPE_INIT) != 0) {
        /* INIT frame */
        uint8_t cmd = header;
        uint16_t bcnt = decode_uint16_be(&packet[5]);

        /* Validate CID */
        if (cid == 0) {
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_CHANNEL);
            return;
        }

        if (cid == CTAPHID_BROADCAST_CID) {
            if (cmd != CTAPHID_CMD_INIT) {
                pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_CHANNEL);
                return;
            }
        } else {
            int ch_idx = find_channel_index(hid, cid);
            if (ch_idx < 0) {
                pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_CHANNEL);
                return;
            }
            hid->channels[ch_idx].last_active_ms = now_ms;
        }

        /* Check channel lock: commands other than CTAPHID_CMD_INIT fail with CTAP1_ERR_CHANNEL_BUSY */
        if (cmd != CTAPHID_CMD_INIT && hid->locked_cid != 0 && hid->locked_cid != cid) {
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_CHANNEL_BUSY);
            return;
        }

        /* Special case: CTAPHID_CMD_INIT (0x86) */
        if (cmd == CTAPHID_CMD_INIT) {
            if (bcnt != 8) {
                pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_LENGTH);
                return;
            }

            /* Resynchronize: abort in-progress transaction on the same CID */
            if (hid->rx.active && hid->rx.cid == cid) {
                hid->rx.active = false;
            }
            if (hid->active_cmd_cid != 0 && hid->active_cmd_cid == cid) {
                hid->cancel_requested = true;
            }

            uint32_t assigned_cid;
            if (cid == CTAPHID_BROADCAST_CID) {
                pk_ctaphid_channel_t *ch = channel_allocate(hid, now_ms);
                assigned_cid = ch->cid;
            } else {
                assigned_cid = cid;
            }

            uint8_t resp[17];
            memcpy(&resp[0], &packet[7], 8);
            encode_uint32_be(&resp[8], assigned_cid);
            resp[12] = 2; /* CTAPHID protocol version */
            resp[13] = PK_FIRMWARE_VERSION_MAJOR;
            resp[14] = PK_FIRMWARE_VERSION_MINOR;
            resp[15] = PK_FIRMWARE_VERSION_BUILD;
            resp[16] = CTAPHID_CAPABILITY_WINK | CTAPHID_CAPABILITY_CBOR;

            pk_ctaphid_send_response(hid, cid, CTAPHID_CMD_INIT, resp, sizeof(resp));
            return;
        }

        /* Special case: CTAPHID_CMD_CANCEL (0x91) */
        if (cmd == CTAPHID_CMD_CANCEL) {
            if (bcnt != 0) {
                pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_LENGTH);
                return;
            }

            if (hid->active_cmd_cid != 0 && hid->active_cmd_cid != cid) {
                /* Cancel received on a channel other than the one running a command */
                return;
            }

            if (hid->rx.active) {
                if (hid->rx.cid == cid) {
                    hid->rx.active = false;
                } else {
                    return;
                }
            }

            hid->cancel_requested = true;
            return;
        }

        /* If a command is currently executing, reject any other command with CHANNEL_BUSY */
        if (hid->active_cmd_cid != 0) {
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_CHANNEL_BUSY);
            return;
        }

        /* In-progress multi-packet transaction conflict check */
        if (hid->rx.active) {
            if (hid->rx.cid != cid) {
                pk_ctaphid_send_error(hid, cid, CTAP1_ERR_CHANNEL_BUSY);
                return;
            } else {
                hid->rx.active = false;
                pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_SEQ);
                return;
            }
        }

        /* Validate command code */
        if (cmd != CTAPHID_CMD_PING &&
            cmd != CTAPHID_CMD_MSG &&
            cmd != CTAPHID_CMD_CBOR &&
            cmd != CTAPHID_CMD_WINK &&
            cmd != CTAPHID_CMD_LOCK) {
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_COMMAND);
            return;
        }

        /* Validate length */
        if (bcnt > PK_CTAP2_MAX_MSG_SIZE) {
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_LENGTH);
            return;
        }
        if (cmd == CTAPHID_CMD_WINK && bcnt != 0) {
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_LENGTH);
            return;
        }
        if ((cmd == CTAPHID_CMD_CBOR || cmd == CTAPHID_CMD_MSG) && bcnt < 1) {
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_LENGTH);
            return;
        }
        if (cmd == CTAPHID_CMD_LOCK && bcnt != 1) {
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_LENGTH);
            return;
        }

        size_t chunk = bcnt < PK_CTAPHID_INIT_PAYLOAD_SIZE ? bcnt : PK_CTAPHID_INIT_PAYLOAD_SIZE;
        if (chunk > 0) {
            memcpy(hid->rx.payload, &packet[7], chunk);
        }

        if (chunk == bcnt) {
            /* Single-packet message: dispatch immediately */
            hid->rx.active = false;
            hid->rx.cmd = cmd;
            hid->rx.total_len = bcnt;
            hid->rx.received_len = bcnt;
            dispatch_command(hid, cid, now_ms);
        } else {
            /* Multi-packet message: begin reassembly */
            hid->rx.active = true;
            hid->rx.cid = cid;
            hid->rx.cmd = cmd;
            hid->rx.total_len = bcnt;
            hid->rx.received_len = (uint16_t)chunk;
            hid->rx.expected_seq = 0;
            hid->rx.start_ms = now_ms;
            hid->rx.last_packet_ms = now_ms;
        }

    } else {
        /* CONT frame */
        uint8_t seq = header;

        /* Validate CID */
        if (cid == 0 || cid == CTAPHID_BROADCAST_CID) {
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_CHANNEL);
            return;
        }

        int ch_idx = find_channel_index(hid, cid);
        if (ch_idx < 0) {
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_CHANNEL);
            return;
        }
        hid->channels[ch_idx].last_active_ms = now_ms;

        if (hid->active_cmd_cid != 0) {
            return;
        }

        /* If no reassembly is active on device, ignore spurious CONT frame */
        if (!hid->rx.active) {
            return;
        }

        /* If another channel is currently reassembling, return CHANNEL_BUSY */
        if (hid->rx.cid != cid) {
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_CHANNEL_BUSY);
            return;
        }

        /* Check sequence number */
        if (seq != hid->rx.expected_seq) {
            hid->rx.active = false;
            pk_ctaphid_send_error(hid, cid, CTAP1_ERR_INVALID_SEQ);
            return;
        }

        uint16_t remaining = hid->rx.total_len - hid->rx.received_len;
        size_t chunk = remaining < PK_CTAPHID_CONT_PAYLOAD_SIZE ? remaining : PK_CTAPHID_CONT_PAYLOAD_SIZE;
        if (chunk > 0) {
            memcpy(hid->rx.payload + hid->rx.received_len, &packet[5], chunk);
        }

        hid->rx.received_len += (uint16_t)chunk;
        hid->rx.expected_seq++;
        hid->rx.last_packet_ms = now_ms;

        if (hid->rx.received_len == hid->rx.total_len) {
            hid->rx.active = false;
            dispatch_command(hid, cid, now_ms);
        }
    }
}

/* Send a complete response payload segmented into 64-byte packets */
void pk_ctaphid_send_response(
    pk_ctaphid_ctx_t *hid,
    uint32_t cid,
    uint8_t cmd,
    const uint8_t *payload,
    size_t len
) {
    if (!hid || !hid->tx_cb) {
        return;
    }

    /* Segment into 64-byte packets (zero-padded) */
    uint8_t pkt[PK_HID_PACKET_SIZE];
    memset(pkt, 0, sizeof(pkt));

    encode_uint32_be(&pkt[0], cid);
    pkt[4] = cmd | CTAPHID_TYPE_INIT;
    encode_uint16_be(&pkt[5], (uint16_t)len);

    size_t init_chunk = len < PK_CTAPHID_INIT_PAYLOAD_SIZE ? len : PK_CTAPHID_INIT_PAYLOAD_SIZE;
    if (init_chunk > 0 && payload != NULL) {
        memcpy(&pkt[7], payload, init_chunk);
    }
    hid->tx_cb(hid->tx_ctx, pkt);

    size_t offset = init_chunk;
    uint8_t seq = 0;
    while (offset < len) {
        memset(pkt, 0, sizeof(pkt));
        encode_uint32_be(&pkt[0], cid);
        pkt[4] = seq & 0x7FU;

        size_t chunk = len - offset;
        if (chunk > PK_CTAPHID_CONT_PAYLOAD_SIZE) {
            chunk = PK_CTAPHID_CONT_PAYLOAD_SIZE;
        }
        if (payload != NULL) {
            memcpy(&pkt[5], payload + offset, chunk);
        }
        hid->tx_cb(hid->tx_ctx, pkt);

        offset += chunk;
        seq++;
    }
}

/* Send a 1-byte CTAPHID_ERROR frame on `cid` */
void pk_ctaphid_send_error(pk_ctaphid_ctx_t *hid, uint32_t cid, uint8_t err_code) {
    if (!hid) {
        return;
    }
    pk_ctaphid_send_response(hid, cid, CTAPHID_CMD_ERROR, &err_code, 1);
}
