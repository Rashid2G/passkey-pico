#ifndef PICO_PASSKEY_USB_HID_H
#define PICO_PASSKEY_USB_HID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "passkey/config.h"
#include "passkey/ctaphid.h"

/* Official 34-byte FIDO Alliance USB HID Report Descriptor:
 *   Usage Page (FIDO Alliance 0xF1D0)
 *   Usage (U2F / FIDO Authenticator 0x01)
 *   Collection (Application)
 *     Usage (Input Report Data 0x20), 64 bytes
 *     Usage (Output Report Data 0x21), 64 bytes
 *   End Collection
 */
#define PK_FIDO_HID_REPORT_DESC_LEN 34U

extern const uint8_t pk_fido_hid_report_desc[PK_FIDO_HID_REPORT_DESC_LEN];

/* USB Device Connection Lifecycle States */
typedef enum {
    PK_USB_STATE_UNMOUNTED = 0,
    PK_USB_STATE_MOUNTED,
    PK_USB_STATE_SUSPENDED
} pk_usb_state_t;

/* Initialize USB device stack and bind to CTAPHID instance */
void pk_usb_init(pk_ctaphid_ctx_t *hid_ctx);

/* Pump USB events and flush outgoing 64-byte HID report queue */
void pk_usb_task(void);

/* Query current USB connection state */
pk_usb_state_t pk_usb_get_state(void);

/* Queue a 64-byte HID report for transmission over the interrupt IN endpoint */
void pk_usb_queue_tx_packet(void *ctx, const uint8_t packet[PK_HID_PACKET_SIZE]);

#endif /* PICO_PASSKEY_USB_HID_H */
