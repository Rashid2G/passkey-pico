#include "passkey/usb_hid.h"
#include "passkey/ctaphid.h"
#include "passkey/config.h"

#include <string.h>

#ifdef PICO_BUILD
#include "tusb.h"
#include "hardware/sync.h"
#endif

#define PK_USB_TX_RING_CAPACITY 64U
#define PK_USB_RX_RING_CAPACITY 32U

static pk_ctaphid_ctx_t *s_hid_ctx = NULL;
static volatile pk_usb_state_t s_usb_state = PK_USB_STATE_UNMOUNTED;

static uint8_t s_tx_ring[PK_USB_TX_RING_CAPACITY][PK_HID_PACKET_SIZE];
static volatile uint16_t s_tx_head = 0;
static volatile uint16_t s_tx_tail = 0;
static volatile uint16_t s_tx_count = 0;

#ifdef PICO_BUILD
static uint8_t s_rx_ring[PK_USB_RX_RING_CAPACITY][PK_HID_PACKET_SIZE];
static volatile uint16_t s_rx_head = 0;
static volatile uint16_t s_rx_tail = 0;
static volatile uint16_t s_rx_count = 0;

static void try_flush_tx(void) {
    uint32_t ints = save_and_disable_interrupts();
    if (s_tx_count > 0 && tud_hid_ready()) {
        uint8_t pkt[PK_HID_PACKET_SIZE];
        memcpy(pkt, s_tx_ring[s_tx_tail], PK_HID_PACKET_SIZE);
        s_tx_tail = (s_tx_tail + 1) % PK_USB_TX_RING_CAPACITY;
        s_tx_count--;
        restore_interrupts(ints);
        tud_hid_report(0, pkt, PK_HID_PACKET_SIZE);
    } else {
        restore_interrupts(ints);
    }
}

static void drain_rx_ring(void) {
    while (s_hid_ctx != NULL) {
        uint8_t pkt[PK_HID_PACKET_SIZE];
        uint32_t ints = save_and_disable_interrupts();
        if (s_rx_count == 0) {
            restore_interrupts(ints);
            break;
        }
        memcpy(pkt, s_rx_ring[s_rx_tail], PK_HID_PACKET_SIZE);
        s_rx_tail = (s_rx_tail + 1) % PK_USB_RX_RING_CAPACITY;
        s_rx_count--;
        restore_interrupts(ints);

        pk_ctaphid_rx_packet(s_hid_ctx, pkt);
        tud_task();
        try_flush_tx();
    }
}
#endif

void pk_usb_init(pk_ctaphid_ctx_t *hid_ctx) {
    s_hid_ctx = hid_ctx;
    s_tx_head = 0;
    s_tx_tail = 0;
    s_tx_count = 0;
    s_usb_state = PK_USB_STATE_UNMOUNTED;

#ifdef PICO_BUILD
    s_rx_head = 0;
    s_rx_tail = 0;
    s_rx_count = 0;
    tusb_init();
#endif
}

void pk_usb_task(void) {
#ifdef PICO_BUILD
    tud_task();
    try_flush_tx();
    drain_rx_ring();
#endif
}

pk_usb_state_t pk_usb_get_state(void) {
    return s_usb_state;
}

void pk_usb_queue_tx_packet(void *ctx, const uint8_t packet[PK_HID_PACKET_SIZE]) {
    (void)ctx;
    if (packet == NULL) {
        return;
    }

#ifdef PICO_BUILD
    /* Avoid piling up duplicate keepalives if TX ring already has pending packets */
    if (packet[4] == CTAPHID_CMD_KEEPALIVE && s_tx_count > 0) {
        tud_task();
        try_flush_tx();
        if (s_tx_count > 0) {
            return;
        }
    }

    /* If TX ring is full for a real response packet, pump USB briefly to free space */
    for (uint32_t spin = 0; s_tx_count >= PK_USB_TX_RING_CAPACITY && spin < 20000U; spin++) {
        tud_task();
        try_flush_tx();
    }

    uint32_t ints = save_and_disable_interrupts();
#endif

    if (s_tx_count < PK_USB_TX_RING_CAPACITY) {
        memcpy(s_tx_ring[s_tx_head], packet, PK_HID_PACKET_SIZE);
        s_tx_head = (s_tx_head + 1) % PK_USB_TX_RING_CAPACITY;
        s_tx_count++;
    }

#ifdef PICO_BUILD
    restore_interrupts(ints);
    try_flush_tx();
#endif
}

#ifdef PICO_BUILD

void tud_mount_cb(void) {
    s_usb_state = PK_USB_STATE_MOUNTED;
}

void tud_umount_cb(void) {
    s_usb_state = PK_USB_STATE_UNMOUNTED;
}

void tud_suspend_cb(bool remote_wakeup_en) {
    (void)remote_wakeup_en;
    s_usb_state = PK_USB_STATE_SUSPENDED;
}

void tud_resume_cb(void) {
    s_usb_state = tud_mounted() ? PK_USB_STATE_MOUNTED : PK_USB_STATE_UNMOUNTED;
}

void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report, uint16_t len) {
    (void)instance;
    (void)report;
    (void)len;
    try_flush_tx();
}

uint16_t tud_hid_get_report_cb(
    uint8_t instance,
    uint8_t report_id,
    hid_report_type_t report_type,
    uint8_t *buffer,
    uint16_t reqlen
) {
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)reqlen;
    return 0;
}

void tud_hid_set_report_cb(
    uint8_t instance,
    uint8_t report_id,
    hid_report_type_t report_type,
    uint8_t const *buffer,
    uint16_t bufsize
) {
    (void)instance;
    (void)report_id;
    (void)report_type;

    if (s_hid_ctx == NULL || buffer == NULL) {
        return;
    }

    uint32_t ints = save_and_disable_interrupts();
    if (s_rx_count < PK_USB_RX_RING_CAPACITY) {
        if (bufsize >= PK_HID_PACKET_SIZE) {
            memcpy(s_rx_ring[s_rx_head], buffer, PK_HID_PACKET_SIZE);
        } else {
            memset(s_rx_ring[s_rx_head], 0, PK_HID_PACKET_SIZE);
            memcpy(s_rx_ring[s_rx_head], buffer, bufsize);
        }
        s_rx_head = (s_rx_head + 1) % PK_USB_RX_RING_CAPACITY;
        s_rx_count++;
    }
    restore_interrupts(ints);
}

#endif /* PICO_BUILD */
