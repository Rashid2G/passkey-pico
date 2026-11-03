#ifndef PICO_PASSKEY_PLATFORM_H
#define PICO_PASSKEY_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "passkey/status.h"

/* User presence confirmation result */
typedef enum {
    PK_UP_CONFIRMED = 0,
    PK_UP_TIMEOUT,
    PK_UP_CANCELLED,
    PK_UP_DENIED
} pk_up_result_t;

/* Callback invoked periodically while waiting for user presence so the
 * transport layer can pump USB tasks, transmit CTAPHID_KEEPALIVE frames,
 * and report whether a CTAPHID_CANCEL command arrived.
 * Returns true if the current operation was cancelled by the host.
 */
typedef bool (*pk_keepalive_cb_t)(void *user_ctx, uint8_t keepalive_status);

/* Hardware Abstraction Layer (HAL) interface.
 * Injecting this struct makes all protocol, crypto, PIN, and storage modules
 * 100% deterministic and unit-testable on host machines without RP2040 silicon.
 */
typedef struct {
    void *ctx;

    /* Monotonic clock in milliseconds since boot */
    uint64_t (*now_ms)(void *ctx);

    /* Hardware entropy source filling `buf` with `len` random bytes */
    pk_err_t (*get_random_bytes)(void *ctx, uint8_t *buf, size_t len);

    /* Device-unique 8-byte board identifier (RP2040 QSPI NOR unique ID) */
    pk_err_t (*get_unique_id)(void *ctx, uint8_t out_id[8]);

    /* Raw NOR flash operations relative to the start of the storage region
     * (offset 0 .. PK_STORAGE_REGION_BYTES - 1):
     * - flash_read: arbitrary byte read
     * - flash_erase_sector: offset must be 4096-byte aligned
     * - flash_program_page: offset & len must be multiples of 256 bytes
     */
    pk_err_t (*flash_read)(void *ctx, uint32_t offset, uint8_t *out, size_t len);
    pk_err_t (*flash_erase_sector)(void *ctx, uint32_t offset);
    pk_err_t (*flash_program_page)(void *ctx, uint32_t offset, const uint8_t *data, size_t len);

    /* Wait up to `timeout_ms` for physical user presence confirmation (button press).
     * Periodically invokes `keepalive_cb(keepalive_ctx, 0x02)` if non-NULL.
     */
    pk_up_result_t (*request_user_presence)(
        void *ctx,
        uint32_t timeout_ms,
        pk_keepalive_cb_t keepalive_cb,
        void *keepalive_ctx
    );

    /* Trigger visual device identification ("wink" LED pattern) */
    void (*wink)(void *ctx);
} pk_platform_t;

#endif /* PICO_PASSKEY_PLATFORM_H */
