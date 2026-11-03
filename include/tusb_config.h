#ifndef PICO_PASSKEY_TUSB_CONFIG_H
#define PICO_PASSKEY_TUSB_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Board & RHPort Configuration for RP2040 */
#ifndef BOARD_TUD_RHPORT
#define BOARD_TUD_RHPORT      0
#endif

#ifndef BOARD_TUD_MAX_SPEED
#define BOARD_TUD_MAX_SPEED   OPT_MODE_FULL_SPEED
#endif

#define CFG_TUSB_RHPORT0_MODE (OPT_MODE_DEVICE | BOARD_TUD_MAX_SPEED)

#ifndef CFG_TUSB_OS
#define CFG_TUSB_OS           OPT_OS_NONE
#endif

#ifndef CFG_TUSB_MEM_SECTION
#define CFG_TUSB_MEM_SECTION
#endif

#ifndef CFG_TUSB_MEM_ALIGN
#define CFG_TUSB_MEM_ALIGN    __attribute__((aligned(4)))
#endif

/* Device Stack Configuration */
#define CFG_TUD_ENDPOINT0_SIZE   64

/* Class Drivers: Enable only Generic HID (FIDO2 CTAPHID) */
#define CFG_TUD_CDC              0
#define CFG_TUD_MSC              0
#define CFG_TUD_HID              1
#define CFG_TUD_MIDI             0
#define CFG_TUD_VENDOR           0

/* FIDO2 CTAPHID uses 64-byte Interrupt IN & OUT reports */
#define CFG_TUD_HID_EP_BUFSIZE   64

#ifdef __cplusplus
}
#endif

#endif /* PICO_PASSKEY_TUSB_CONFIG_H */
