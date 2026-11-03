#ifndef PICO_PASSKEY_CONFIG_H
#define PICO_PASSKEY_CONFIG_H

#include <stdint.h>

/* Firmware & USB Device Metadata */
#define PK_FIRMWARE_VERSION_MAJOR 1
#define PK_FIRMWARE_VERSION_MINOR 0
#define PK_FIRMWARE_VERSION_BUILD 0

#ifndef PK_USB_VID
#define PK_USB_VID 0x2E8A /* Raspberry Pi Foundation VID (configurable) */
#endif

#ifndef PK_USB_PID
#define PK_USB_PID 0xF1D0 /* FIDO2 Authenticator Product ID */
#endif

#define PK_USB_MANUFACTURER_STR "Pico Passkey"
#define PK_USB_PRODUCT_STR      "Pico Passkey FIDO2 Security Key"

/* Authenticator AAGUID (16 bytes): "f1d02040-7069-636f-8000-706173736b65" */
#define PK_AAGUID_BYTES \
    { 0xF1, 0xD0, 0x20, 0x40, 0x70, 0x69, 0x63, 0x6F, \
      0x80, 0x00, 0x70, 0x61, 0x73, 0x73, 0x6B, 0x65 }

/* USB HID & CTAPHID Parameters */
#define PK_HID_PACKET_SIZE            64U
#define PK_CTAPHID_INIT_PAYLOAD_SIZE  (PK_HID_PACKET_SIZE - 7U) /* 57 bytes */
#define PK_CTAPHID_CONT_PAYLOAD_SIZE  (PK_HID_PACKET_SIZE - 5U) /* 59 bytes */
#define PK_CTAPHID_MAX_SEQ            128U
#define PK_CTAPHID_MAX_PAYLOAD_SIZE   7609U /* 57 + 128 * 59 */
#define PK_CTAPHID_MAX_CHANNELS       8U
#define PK_CTAPHID_TRANS_TIMEOUT_MS   500U
#define PK_CTAPHID_KEEPALIVE_MS       100U
#define PK_CTAPHID_MAX_LOCK_SECONDS   10U

/* CTAP2 Protocol Limits */
#define PK_CTAP2_MAX_MSG_SIZE         2048U
#define PK_CTAP2_MAX_CRED_COUNT_LIST  16U
#define PK_CTAP2_MAX_CRED_ID_LEN      128U
#define PK_CRED_ID_NONRESIDENT_LEN    64U
#define PK_CRED_ID_RESIDENT_LEN       64U
#define PK_RP_ID_MAX_LEN              128U
#define PK_USER_ID_MAX_LEN            64U
#define PK_USER_NAME_MAX_LEN          64U
#define PK_USER_DISPLAY_MAX_LEN       64U

/* User Presence & Reset Timeouts */
#define PK_UP_TIMEOUT_MS              15000U /* 15 seconds to touch key */
#define PK_RESET_WINDOW_MS            10000U /* 10 seconds after boot for reset */
#define PK_MULTI_ASSERTION_TIMEOUT_MS 30000U /* 30 seconds for GetNextAssertion */

/* PIN Policy & Retry Limits */
#define PK_PIN_MIN_LEN                4U
#define PK_PIN_MAX_LEN                63U
#define PK_PIN_PADDED_LEN             64U
#define PK_PIN_MAX_RETRIES            8U
#define PK_PIN_BOOT_RETRIES           3U
#define PK_PIN_TOKEN_LEN              32U
#define PK_PIN_TOKEN_TIMEOUT_MS       60000U /* 60 seconds token validity */

/* Flash Storage Layout (Top 128 KiB of 2 MiB RP2040 NOR Flash) */
#define PK_FLASH_TOTAL_BYTES          (2U * 1024U * 1024U)
#define PK_FLASH_SECTOR_SIZE          4096U
#define PK_FLASH_PAGE_SIZE            256U
#define PK_STORAGE_REGION_SECTORS     32U /* 128 KiB total */
#define PK_STORAGE_REGION_BYTES       (PK_STORAGE_REGION_SECTORS * PK_FLASH_SECTOR_SIZE)
#define PK_STORAGE_FLASH_OFFSET       (PK_FLASH_TOTAL_BYTES - PK_STORAGE_REGION_BYTES)

/* Sector partitioning within the 32-sector storage region:
 *   Sector 0: State A (A/B journaled device keys + PIN state)
 *   Sector 1: State B (A/B journaled device keys + PIN state)
 *   Sector 2: Counter Log A (append-only monotonic signature counter)
 *   Sector 3: Counter Log B (append-only monotonic signature counter)
 *   Sectors 4..31 (28 sectors): Wear-leveled Resident Credential Pool
 *     4 slots per 4 KiB sector (1024 bytes / 4 pages per slot) = 112 slots
 *     Max active resident credentials capped at 64 to ensure free wear-leveling headroom.
 */
#define PK_STORAGE_STATE_SECTOR_A     0U
#define PK_STORAGE_STATE_SECTOR_B     1U
#define PK_STORAGE_COUNTER_SECTOR_A   2U
#define PK_STORAGE_COUNTER_SECTOR_B   3U
#define PK_STORAGE_CRED_FIRST_SECTOR  4U
#define PK_STORAGE_CRED_SECTOR_COUNT  28U
#define PK_STORAGE_SLOTS_PER_SECTOR   4U
#define PK_STORAGE_SLOT_SIZE          1024U
#define PK_STORAGE_TOTAL_SLOTS        (PK_STORAGE_CRED_SECTOR_COUNT * PK_STORAGE_SLOTS_PER_SECTOR)
#define PK_STORAGE_MAX_RESIDENT_CREDS 64U

#endif /* PICO_PASSKEY_CONFIG_H */
