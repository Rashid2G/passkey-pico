#include "passkey/usb_hid.h"
#include "passkey/config.h"

/* Official 34-byte FIDO Alliance HID Report Descriptor:
 * Usage Page (FIDO Alliance 0xF1D0)
 * Usage (U2F / FIDO Authenticator 0x01)
 * Collection (Application)
 *   Usage (Input Report Data 0x20), 64 bytes
 *   Usage (Output Report Data 0x21), 64 bytes
 * End Collection
 */
const uint8_t pk_fido_hid_report_desc[PK_FIDO_HID_REPORT_DESC_LEN] = {
    0x06, 0xD0, 0xF1,
    0x09, 0x01,
    0xA1, 0x01,
    0x09, 0x20,
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,
    0x81, 0x02,
    0x09, 0x21,
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,
    0x91, 0x02,
    0xC0
};

#ifdef PICO_BUILD

#include "tusb.h"
#include "pico/unique_id.h"
#include <stdio.h>
#include <string.h>

#define ITF_NUM_HID   0
#define ITF_NUM_TOTAL 1

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN)

/* USB Device Descriptor (USB 2.0, class at interface level, VID/PID from config) */
static const tusb_desc_device_t desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,

    .idVendor           = PK_USB_VID,
    .idProduct          = PK_USB_PID,
    .bcdDevice          = 0x0100,

    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,

    .bNumConfigurations = 0x01
};

uint8_t const * tud_descriptor_device_cb(void) {
    return (uint8_t const *)&desc_device;
}

uint8_t const * tud_hid_descriptor_report_cb(uint8_t instance) {
    (void)instance;
    return pk_fido_hid_report_desc;
}

uint8_t const * tud_descriptor_hid_report_cb(uint8_t instance) {
    (void)instance;
    return pk_fido_hid_report_desc;
}

/* USB Configuration Descriptor (1 HID interface, 64-byte IN/OUT EPs, 5ms polling) */
static const uint8_t desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x80, 100),
    TUD_HID_INOUT_DESCRIPTOR(0, 0, HID_ITF_PROTOCOL_NONE, sizeof(pk_fido_hid_report_desc), 0x01, 0x81, CFG_TUD_HID_EP_BUFSIZE, 5)
};

uint8_t const * tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;
    return desc_configuration;
}

enum {
    STRID_LANGID = 0,
    STRID_MANUFACTURER,
    STRID_PRODUCT,
    STRID_SERIAL,
};

static uint16_t desc_str[64];

uint16_t const * tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    size_t chr_count = 0;

    if (index == STRID_LANGID) {
        desc_str[1] = 0x0409;
        chr_count = 1;
    } else {
        const char *str = NULL;
        char serial_buf[17];

        if (index == STRID_MANUFACTURER) {
            str = PK_USB_MANUFACTURER_STR;
        } else if (index == STRID_PRODUCT) {
            str = PK_USB_PRODUCT_STR;
        } else if (index == STRID_SERIAL) {
            pico_unique_board_id_t board_id;
            pico_get_unique_board_id(&board_id);
            for (size_t i = 0; i < 8; ++i) {
                snprintf(&serial_buf[i * 2], 3, "%02X", board_id.id[i]);
            }
            serial_buf[16] = '\0';
            str = serial_buf;
        } else {
            return NULL;
        }

        chr_count = strlen(str);
        if (chr_count > 63) {
            chr_count = 63;
        }

        for (size_t i = 0; i < chr_count; ++i) {
            desc_str[1 + i] = (uint16_t)str[i];
        }
    }

    desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));
    return desc_str;
}

#endif /* PICO_BUILD */
