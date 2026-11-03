#ifndef PICO_PASSKEY_MOCK_PLATFORM_H
#define PICO_PASSKEY_MOCK_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "passkey/config.h"
#include "passkey/platform.h"

typedef struct {
    uint64_t      now_ms;
    uint32_t      prng_state;
    uint8_t       unique_id[8];
    uint8_t       flash[PK_STORAGE_REGION_BYTES];
    uint32_t      sector_erase_counts[PK_STORAGE_REGION_SECTORS];
    uint32_t      page_program_counts;
    pk_up_result_t next_up_result;
    uint32_t      up_requests_count;
    uint32_t      wink_count;
    bool          simulate_keepalive_ticks;
    uint32_t      keepalive_ticks_to_run;
    /* Fault injection hooks for storage recovery testing */
    bool          fail_after_pages;
    uint32_t      pages_remaining_before_fail;
    /* Fault injection hook for RNG failure */
    bool          rng_failure;
} pk_mock_platform_state_t;

void pk_mock_platform_init(pk_mock_platform_state_t *mock, pk_platform_t *out_platform);
void pk_mock_platform_advance_time(pk_mock_platform_state_t *mock, uint64_t delta_ms);

#endif /* PICO_PASSKEY_MOCK_PLATFORM_H */
