#include "passkey/platform.h"
#include "passkey/config.h"
#include "passkey/crypto.h"
#include "passkey/status.h"
#include "passkey/usb_hid.h"
#include "passkey/ctaphid.h"

#include "pico/stdlib.h"
#include "pico/platform.h"
#include "pico/rand.h"
#include "pico/unique_id.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "hardware/gpio.h"
#include "hardware/structs/rosc.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"

#include <string.h>

#define PK_EXTERNAL_BUTTON_PIN 14

#ifndef PICO_DEFAULT_LED_PIN
#define PICO_DEFAULT_LED_PIN 25
#endif

/* Safely read QSPI CSN pin (BOOTSEL button) with interrupts disabled from RAM */
static bool __no_inline_not_in_flash_func(pk_get_bootsel_button)(void) {
    const uint CS_PIN_INDEX = 1;

    uint32_t flags = save_and_disable_interrupts();

    /* Set chip select to Hi-Z */
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    for (volatile int i = 0; i < 1000; ++i) {
        /* Busy wait while CS line stabilizes in Hi-Z */
    }

    /* The BOOTSEL button pulls CSN low when pressed */
    bool pressed = !(sio_hw->gpio_hi_in & (1u << 1));

    /* Restore chip select drive to normal */
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    restore_interrupts(flags);

    return pressed;
}

static void wait_bootsel_released(uint32_t max_wait_ms) {
    uint64_t start = to_ms_since_boot(get_absolute_time());
    while (pk_get_bootsel_button()) {
        if (to_ms_since_boot(get_absolute_time()) - start >= max_wait_ms) {
            break;
        }
        pk_usb_task();
        sleep_ms(2);
    }
}

static uint64_t pico_now_ms(void *ctx) {
    (void)ctx;
    return to_ms_since_boot(get_absolute_time());
}

static uint64_t s_entropy_counter = 0;

static pk_err_t pico_get_random_bytes(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    if (buf == NULL && len > 0) {
        return PK_ERR_INVALID_ARG;
    }
    if (len == 0) {
        return PK_OK;
    }

    size_t offset = 0;
    while (offset < len) {
        struct {
            uint64_t rand64;
            uint64_t timestamp;
            uint64_t counter;
            uint32_t rosc_bits[2];
        } entropy_sample;

        entropy_sample.rand64 = get_rand_64();
        entropy_sample.timestamp = time_us_64();
        entropy_sample.counter = ++s_entropy_counter;

        entropy_sample.rosc_bits[0] = 0;
        entropy_sample.rosc_bits[1] = 0;
        for (int i = 0; i < 32; i++) {
            entropy_sample.rosc_bits[0] = (entropy_sample.rosc_bits[0] << 1) | (rosc_hw->randombit & 1u);
        }
        for (int i = 0; i < 32; i++) {
            entropy_sample.rosc_bits[1] = (entropy_sample.rosc_bits[1] << 1) | (rosc_hw->randombit & 1u);
        }

        uint8_t hash[32];
        pk_err_t err = pk_crypto_sha256((const uint8_t *)&entropy_sample, sizeof(entropy_sample), hash);
        pk_crypto_zeroize(&entropy_sample, sizeof(entropy_sample));
        if (err != PK_OK) {
            pk_crypto_zeroize(hash, sizeof(hash));
            return PK_ERR_CRYPTO;
        }

        size_t chunk = len - offset;
        if (chunk > 32) {
            chunk = 32;
        }
        memcpy(buf + offset, hash, chunk);
        pk_crypto_zeroize(hash, sizeof(hash));
        offset += chunk;
    }

    return PK_OK;
}

/* Mbed TLS hardware entropy poll callback */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;
    if (output == NULL || olen == NULL) {
        return -1;
    }
    if (pico_get_random_bytes(NULL, output, len) != PK_OK) {
        return -1;
    }
    *olen = len;
    return 0;
}

static pk_err_t pico_get_unique_id(void *ctx, uint8_t out_id[8]) {
    (void)ctx;
    if (out_id == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    pico_unique_board_id_t board_id;
    pico_get_unique_board_id(&board_id);
    memcpy(out_id, board_id.id, 8);
    return PK_OK;
}

static pk_err_t pico_flash_read(void *ctx, uint32_t offset, uint8_t *out, size_t len) {
    (void)ctx;
    if (out == NULL || offset > PK_STORAGE_REGION_BYTES ||
        len > PK_STORAGE_REGION_BYTES - offset) {
        return PK_ERR_INVALID_ARG;
    }

    const uint8_t *flash_target = (const uint8_t *)(XIP_BASE + PK_STORAGE_FLASH_OFFSET + offset);
    memcpy(out, flash_target, len);
    return PK_OK;
}

static pk_err_t pico_flash_erase_sector(void *ctx, uint32_t offset) {
    (void)ctx;
    if (offset % PK_FLASH_SECTOR_SIZE != 0 ||
        offset >= PK_STORAGE_REGION_BYTES) {
        return PK_ERR_INVALID_ARG;
    }

    wait_bootsel_released(500);
    pk_usb_task();

    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(PK_STORAGE_FLASH_OFFSET + offset, PK_FLASH_SECTOR_SIZE);
    restore_interrupts(ints);

    pk_usb_task();
    return PK_OK;
}

static pk_err_t pico_flash_program_page(
    void *ctx,
    uint32_t offset,
    const uint8_t *data,
    size_t len
) {
    (void)ctx;
    if (data == NULL || len == 0 ||
        offset % PK_FLASH_PAGE_SIZE != 0 ||
        len % PK_FLASH_PAGE_SIZE != 0 ||
        offset > PK_STORAGE_REGION_BYTES ||
        len > PK_STORAGE_REGION_BYTES - offset) {
        return PK_ERR_INVALID_ARG;
    }

    wait_bootsel_released(500);
    pk_usb_task();

    uint32_t ints = save_and_disable_interrupts();
    flash_range_program(PK_STORAGE_FLASH_OFFSET + offset, data, len);
    restore_interrupts(ints);

    pk_usb_task();
    return PK_OK;
}

static pk_up_result_t pico_request_user_presence(
    void *ctx,
    uint32_t timeout_ms,
    pk_keepalive_cb_t keepalive_cb,
    void *keepalive_ctx
) {
    (void)ctx;
    uint64_t start = to_ms_since_boot(get_absolute_time());
    uint64_t last_keepalive = start;
    uint64_t last_led_toggle = start;
    bool led_state = false;
    uint64_t button_press_start = 0;

    while (1) {
        pk_usb_task();

        uint64_t now = to_ms_since_boot(get_absolute_time());

        /* CTAPHID keepalive heartbeat every 50ms */
        if (keepalive_cb != NULL && (now - last_keepalive >= 50)) {
            last_keepalive = now;
            if (keepalive_cb(keepalive_ctx, CTAPHID_STATUS_UPNEEDED)) {
                gpio_put(PICO_DEFAULT_LED_PIN, 0);
                return PK_UP_CANCELLED;
            }
        }

        /* Rapid LED blinking (100ms period: toggle every 50ms) to prompt user to press button */
        if (now - last_led_toggle >= 50) {
            last_led_toggle = now;
            led_state = !led_state;
            gpio_put(PICO_DEFAULT_LED_PIN, led_state ? 1 : 0);
        }

        /* Physical button check (BOOTSEL or GPIO 14 active low) with 25ms debounce */
        bool btn_pressed = pk_get_bootsel_button() || (gpio_get(PK_EXTERNAL_BUTTON_PIN) == 0);
        if (btn_pressed) {
            if (button_press_start == 0) {
                button_press_start = now;
            } else if (now - button_press_start >= 25) {
                wait_bootsel_released(500);
                gpio_put(PICO_DEFAULT_LED_PIN, 1);
                return PK_UP_CONFIRMED;
            }
        } else {
            button_press_start = 0;
        }

        if (timeout_ms > 0 && (now - start >= timeout_ms)) {
            gpio_put(PICO_DEFAULT_LED_PIN, 0);
            return PK_UP_TIMEOUT;
        }

        sleep_ms(2);
    }
}

static void pico_wink(void *ctx) {
    (void)ctx;
    for (int i = 0; i < 5; i++) {
        gpio_put(PICO_DEFAULT_LED_PIN, 1);
        for (int t = 0; t < 20; t++) {
            pk_usb_task();
            sleep_ms(5);
        }
        gpio_put(PICO_DEFAULT_LED_PIN, 0);
        for (int t = 0; t < 20; t++) {
            pk_usb_task();
            sleep_ms(5);
        }
    }
}

void pk_platform_pico_init(pk_platform_t *out_platform) {
    if (out_platform == NULL) {
        return;
    }

    out_platform->ctx = NULL;
    out_platform->now_ms = pico_now_ms;
    out_platform->get_random_bytes = pico_get_random_bytes;
    out_platform->get_unique_id = pico_get_unique_id;
    out_platform->flash_read = pico_flash_read;
    out_platform->flash_erase_sector = pico_flash_erase_sector;
    out_platform->flash_program_page = pico_flash_program_page;
    out_platform->request_user_presence = pico_request_user_presence;
    out_platform->wink = pico_wink;

    /* Initialize onboard status LED */
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
    gpio_put(PICO_DEFAULT_LED_PIN, 0);

    /* Initialize optional external user-presence button on GPIO 14 */
    gpio_init(PK_EXTERNAL_BUTTON_PIN);
    gpio_set_dir(PK_EXTERNAL_BUTTON_PIN, GPIO_IN);
    gpio_pull_up(PK_EXTERNAL_BUTTON_PIN);
}
