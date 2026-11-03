#include "pico/stdlib.h"
#include "passkey/platform.h"
#include "passkey/crypto.h"
#include "passkey/storage.h"
#include "passkey/pin.h"
#include "passkey/ctap2.h"
#include "passkey/ctaphid.h"
#include "passkey/usb_hid.h"

#ifndef PICO_DEFAULT_LED_PIN
#define PICO_DEFAULT_LED_PIN 25
#endif

void pk_platform_pico_init(pk_platform_t *out_platform);

static pk_platform_t  s_platform;
static pk_crypto_ctx_t  s_crypto;
static pk_storage_ctx_t s_storage;
static pk_pin_ctx_t     s_pin;
static pk_ctap2_ctx_t   s_ctap2;
static pk_ctaphid_ctx_t s_ctaphid;

int main(void) {
    stdio_init_all();

    pk_platform_pico_init(&s_platform);
    pk_crypto_init(&s_crypto, &s_platform);
    pk_storage_init(&s_storage, &s_platform, &s_crypto);
    pk_pin_init(&s_pin, &s_platform, &s_crypto, &s_storage);
    pk_ctap2_init(&s_ctap2, &s_platform, &s_crypto, &s_storage, &s_pin);
    pk_ctaphid_init(&s_ctaphid, &s_platform, &s_ctap2, pk_usb_queue_tx_packet, NULL);
    pk_usb_init(&s_ctaphid);

    while (1) {
        pk_usb_task();
        pk_ctaphid_check_timeouts(&s_ctaphid);

        /* Update status LED heartbeat when mounted (50ms pulse every 1000ms) */
        uint64_t now = s_platform.now_ms(s_platform.ctx);
        pk_usb_state_t usb_state = pk_usb_get_state();
        if (usb_state == PK_USB_STATE_MOUNTED) {
            uint32_t phase = (uint32_t)(now % 1000);
            gpio_put(PICO_DEFAULT_LED_PIN, (phase < 50) ? 1 : 0);
        } else {
            gpio_put(PICO_DEFAULT_LED_PIN, 0);
        }
    }

    return 0;
}
