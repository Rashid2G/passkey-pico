#include "mock_platform.h"
#include <string.h>

static uint64_t mock_now_ms(void *ctx)
{
    pk_mock_platform_state_t *m = (pk_mock_platform_state_t *)ctx;
    return m->now_ms;
}

static pk_err_t mock_get_random_bytes(void *ctx, uint8_t *buf, size_t len)
{
    pk_mock_platform_state_t *m = (pk_mock_platform_state_t *)ctx;
    if (m->rng_failure) {
        return PK_ERR_CRYPTO;
    }
    if (buf == NULL && len > 0) {
        return PK_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < len; ++i) {
        /* xorshift32 for deterministic, reproducible host tests */
        uint32_t x = m->prng_state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        m->prng_state = x;
        buf[i] = (uint8_t)(x & 0xFFU);
    }
    return PK_OK;
}

static pk_err_t mock_get_unique_id(void *ctx, uint8_t out_id[8])
{
    pk_mock_platform_state_t *m = (pk_mock_platform_state_t *)ctx;
    if (out_id == NULL) {
        return PK_ERR_INVALID_ARG;
    }
    memcpy(out_id, m->unique_id, 8);
    return PK_OK;
}

static pk_err_t mock_flash_read(void *ctx, uint32_t offset, uint8_t *out, size_t len)
{
    pk_mock_platform_state_t *m = (pk_mock_platform_state_t *)ctx;
    if (out == NULL || offset + len > PK_STORAGE_REGION_BYTES) {
        return PK_ERR_INVALID_ARG;
    }
    memcpy(out, &m->flash[offset], len);
    return PK_OK;
}

static pk_err_t mock_flash_erase_sector(void *ctx, uint32_t offset)
{
    pk_mock_platform_state_t *m = (pk_mock_platform_state_t *)ctx;
    if ((offset % PK_FLASH_SECTOR_SIZE) != 0 ||
        offset + PK_FLASH_SECTOR_SIZE > PK_STORAGE_REGION_BYTES) {
        return PK_ERR_INVALID_ARG;
    }
    memset(&m->flash[offset], 0xFF, PK_FLASH_SECTOR_SIZE);
    m->sector_erase_counts[offset / PK_FLASH_SECTOR_SIZE]++;
    return PK_OK;
}

static pk_err_t mock_flash_program_page(
    void *ctx,
    uint32_t offset,
    const uint8_t *data,
    size_t len)
{
    pk_mock_platform_state_t *m = (pk_mock_platform_state_t *)ctx;
    if (data == NULL || len == 0 ||
        (offset % PK_FLASH_PAGE_SIZE) != 0 ||
        (len % PK_FLASH_PAGE_SIZE) != 0 ||
        offset + len > PK_STORAGE_REGION_BYTES) {
        return PK_ERR_INVALID_ARG;
    }

    size_t pages = len / PK_FLASH_PAGE_SIZE;
    for (size_t p = 0; p < pages; ++p) {
        if (m->fail_after_pages) {
            if (m->pages_remaining_before_fail == 0) {
                return PK_ERR_FLASH_IO;
            }
            m->pages_remaining_before_fail--;
        }
        uint32_t page_off = offset + (uint32_t)(p * PK_FLASH_PAGE_SIZE);
        const uint8_t *src = data + (p * PK_FLASH_PAGE_SIZE);
        for (size_t i = 0; i < PK_FLASH_PAGE_SIZE; ++i) {
            /* Emulate real NOR flash physics: bits can only transition 1 -> 0 */
            m->flash[page_off + i] &= src[i];
        }
        m->page_program_counts++;
    }
    return PK_OK;
}

static pk_up_result_t mock_request_user_presence(
    void *ctx,
    uint32_t timeout_ms,
    pk_keepalive_cb_t keepalive_cb,
    void *keepalive_ctx)
{
    (void)timeout_ms;
    pk_mock_platform_state_t *m = (pk_mock_platform_state_t *)ctx;
    m->up_requests_count++;

    if (m->simulate_keepalive_ticks && keepalive_cb != NULL) {
        for (uint32_t i = 0; i < m->keepalive_ticks_to_run; ++i) {
            m->now_ms += 100U;
            if (keepalive_cb(keepalive_ctx, 0x02U)) {
                return PK_UP_CANCELLED;
            }
        }
    }

    return m->next_up_result;
}

static void mock_wink(void *ctx)
{
    pk_mock_platform_state_t *m = (pk_mock_platform_state_t *)ctx;
    m->wink_count++;
}

void pk_mock_platform_init(pk_mock_platform_state_t *mock, pk_platform_t *out_platform)
{
    memset(mock, 0, sizeof(*mock));
    mock->now_ms = 1000ULL;
    mock->prng_state = 0xCAFEBABEUL;
    const uint8_t default_uid[8] = { 0xE6, 0x61, 0x41, 0x03, 0xE7, 0x4F, 0x2A, 0x2B };
    memcpy(mock->unique_id, default_uid, 8);
    memset(mock->flash, 0xFF, sizeof(mock->flash));
    mock->next_up_result = PK_UP_CONFIRMED;
    mock->rng_failure = false;

    out_platform->ctx = mock;
    out_platform->now_ms = mock_now_ms;
    out_platform->get_random_bytes = mock_get_random_bytes;
    out_platform->get_unique_id = mock_get_unique_id;
    out_platform->flash_read = mock_flash_read;
    out_platform->flash_erase_sector = mock_flash_erase_sector;
    out_platform->flash_program_page = mock_flash_program_page;
    out_platform->request_user_presence = mock_request_user_presence;
    out_platform->wink = mock_wink;
}

void pk_mock_platform_advance_time(pk_mock_platform_state_t *mock, uint64_t delta_ms)
{
    mock->now_ms += delta_ms;
}
