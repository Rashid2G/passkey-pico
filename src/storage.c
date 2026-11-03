#include "passkey/storage.h"
#include <string.h>

/*
 * On-flash Record Structures (Packed and Aligned to Flash Page Size: 256 bytes)
 */

/* Device persistent state record stored in A/B sectors 0 & 1 (Page 0 of sector) */
typedef struct {
    uint32_t magic;         /* PK_STORAGE_STATE_MAGIC (0x32534B50UL) */
    uint16_t version;       /* PK_STORAGE_VERSION (1U) */
    uint16_t reserved;      /* 0 */
    uint32_t generation;   /* Monotonic state generation */
    pk_device_state_t state;
    uint8_t padding[252 - (12 + sizeof(pk_device_state_t))];
    uint32_t crc32;         /* IEEE 802.3 CRC32 over the first 252 bytes */
} pk_flash_state_record_t;

_Static_assert(sizeof(pk_flash_state_record_t) == PK_FLASH_PAGE_SIZE,
               "pk_flash_state_record_t must be exactly 256 bytes");
_Static_assert(offsetof(pk_flash_state_record_t, crc32) == 252,
               "State record CRC32 must be at offset 252");

/* Monotonic counter page stored in append-only counter sectors 2 & 3 */
typedef struct {
    uint32_t magic;         /* PK_STORAGE_CNT_MAGIC (0x314E4B50UL) */
    uint32_t counter_val;   /* Global sign counter */
    uint8_t padding[244];   /* Padding to 252 bytes */
    uint32_t crc32;         /* IEEE 802.3 CRC32 over the first 252 bytes */
} pk_flash_counter_page_t;

_Static_assert(sizeof(pk_flash_counter_page_t) == PK_FLASH_PAGE_SIZE,
               "pk_flash_counter_page_t must be exactly 256 bytes");
_Static_assert(offsetof(pk_flash_counter_page_t, crc32) == 252,
               "Counter page CRC32 must be at offset 252");

/* Credential payload stored across Pages 0, 1, and 2 (768 bytes total) of a 1024-byte slot */
typedef struct {
    uint32_t magic;                                             /* PK_STORAGE_CRED_MAGIC (0x31434B50UL) */
    uint32_t write_seq;                                         /* Creation sequence */
    uint32_t erase_count;                                       /* Sector erase count */
    uint32_t use_count;                                         /* Credential use counter */
    uint8_t cred_Provide_up_uv_flags;
    uint8_t cred_id[PK_CRED_ID_RESIDENT_LEN];                   /* 64 bytes */
    uint8_t cred_random[32];
    uint8_t priv_key[PK_P256_PRIVKEY_LEN];                     /* 32 bytes */
    pk_p256_pubkey_t pub_key;                                   /* 64 bytes */
    uint8_t rp_id_hash[32];
    char rp_id[PK_RP_ID_MAX_LEN];                               /* 128 bytes */
    uint8_t user_id_len;
    uint8_t user_id[PK_USER_ID_MAX_LEN];                       /* 64 bytes */
    char user_name[PK_USER_NAME_MAX_LEN];                       /* 64 bytes */
    char user_display_name[PK_USER_DISPLAY_MAX_LEN];           /* 64 bytes */
    uint8_t hmac_secret_enabled;
    uint8_t reserved[3];                                        /* Alignment padding */
    uint8_t padding[198];                                       /* Pad to 764 bytes */
    uint32_t crc32;                                             /* CRC32 over first 764 bytes */
} pk_flash_cred_payload_t;

_Static_assert(sizeof(pk_flash_cred_payload_t) == 3 * PK_FLASH_PAGE_SIZE,
               "pk_flash_cred_payload_t must be exactly 768 bytes (3 pages)");
_Static_assert(offsetof(pk_flash_cred_payload_t, crc32) == 764,
               "Credential payload CRC32 must be at offset 764");

/* Slot lifecycle status */
typedef enum {
    SLOT_STATE_EMPTY = 0,
    SLOT_STATE_ACTIVE,
    SLOT_STATE_TOMBSTONE
} slot_state_t;

/* Helper: compute byte offset for credential slot within storage region */
static inline uint32_t get_slot_offset(uint16_t slot_index) {
    uint32_t sec = PK_STORAGE_CRED_FIRST_SECTOR + (slot_index / PK_STORAGE_SLOTS_PER_SECTOR);
    uint32_t slot_in_sec = slot_index % PK_STORAGE_SLOTS_PER_SECTOR;
    return sec * PK_FLASH_SECTOR_SIZE + slot_in_sec * PK_STORAGE_SLOT_SIZE;
}

/* Helper: check if buffer is all 0xFF (erased NOR flash) */
static bool is_buffer_all_ff(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0xFFU) {
            return false;
        }
    }
    return true;
}

/* Helper: check if Page 3 of a slot has tombstone marker */
static bool is_page3_tombstone(pk_storage_ctx_t *storage, uint32_t slot_offset) {
    uint8_t page3[PK_FLASH_PAGE_SIZE];
    uint32_t page3_offset = slot_offset + 3U * PK_FLASH_PAGE_SIZE;
    pk_err_t err = storage->platform->flash_read(storage->platform->ctx, page3_offset, page3, sizeof(page3));
    if (err != PK_OK) {
        return false;
    }
    for (size_t i = 0; i < sizeof(page3); i++) {
        if (page3[i] != 0xFFU) {
            return true;
        }
    }
    return false;
}

/* Helper: read and determine status of a credential slot */
static slot_state_t get_slot_state(
    pk_storage_ctx_t *storage,
    uint16_t slot_index,
    pk_flash_cred_payload_t *out_payload
) {
    uint32_t slot_offset = get_slot_offset(slot_index);

    if (is_page3_tombstone(storage, slot_offset)) {
        if (out_payload) {
            (void)storage->platform->flash_read(
                storage->platform->ctx,
                slot_offset,
                (uint8_t *)out_payload,
                sizeof(*out_payload)
            );
        }
        return SLOT_STATE_TOMBSTONE;
    }

    pk_flash_cred_payload_t temp;
    pk_flash_cred_payload_t *p = out_payload ? out_payload : &temp;
    pk_err_t err = storage->platform->flash_read(
        storage->platform->ctx,
        slot_offset,
        (uint8_t *)p,
        sizeof(*p)
    );
    if (err != PK_OK) {
        return SLOT_STATE_TOMBSTONE;
    }

    if (p->magic == PK_STORAGE_CRED_MAGIC) {
        uint32_t computed_crc = pk_crc32((const uint8_t *)p, 764);
        if (p->crc32 == computed_crc) {
            return SLOT_STATE_ACTIVE;
        }
    }

    if (is_buffer_all_ff((const uint8_t *)p, sizeof(*p))) {
        return SLOT_STATE_EMPTY;
    }

    /* Incomplete / corrupted write: treat as tombstone so sector compaction cleans it */
    return SLOT_STATE_TOMBSTONE;
}

/* Helper: mark slot as tombstone by programming Page 3 with 0x00 bytes */
static pk_err_t tombstone_slot(pk_storage_ctx_t *storage, uint16_t slot_index) {
    uint32_t slot_offset = get_slot_offset(slot_index);
    uint32_t page3_offset = slot_offset + 3U * PK_FLASH_PAGE_SIZE;
    uint8_t zero_page[PK_FLASH_PAGE_SIZE];
    memset(zero_page, 0x00, sizeof(zero_page));

    pk_err_t err = storage->platform->flash_program_page(
        storage->platform->ctx,
        page3_offset,
        zero_page,
        sizeof(zero_page)
    );
    if (err != PK_OK) {
        return err;
    }

    uint8_t readback[PK_FLASH_PAGE_SIZE];
    err = storage->platform->flash_read(storage->platform->ctx, page3_offset, readback, sizeof(readback));
    if (err != PK_OK) {
        return err;
    }
    if (readback[0] != 0x00U) {
        return PK_ERR_FLASH_IO;
    }

    return PK_OK;
}

/* Helper: program Pages 0..2 for a credential slot and verify readback */
static pk_err_t write_cred_slot(
    pk_storage_ctx_t *storage,
    uint16_t slot_index,
    const pk_flash_cred_payload_t *payload
) {
    uint32_t slot_offset = get_slot_offset(slot_index);
    const uint8_t *data = (const uint8_t *)payload;

    for (size_t p = 0; p < 3; p++) {
        pk_err_t err = storage->platform->flash_program_page(
            storage->platform->ctx,
            slot_offset + (uint32_t)(p * PK_FLASH_PAGE_SIZE),
            data + p * PK_FLASH_PAGE_SIZE,
            PK_FLASH_PAGE_SIZE
        );
        if (err != PK_OK) {
            return err;
        }
    }

    /* Verify readback */
    pk_flash_cred_payload_t readback;
    pk_err_t err = storage->platform->flash_read(
        storage->platform->ctx,
        slot_offset,
        (uint8_t *)&readback,
        sizeof(readback)
    );
    if (err != PK_OK) {
        pk_crypto_zeroize(&readback, sizeof(readback));
        return err;
    }
    bool match = (readback.magic == PK_STORAGE_CRED_MAGIC &&
                  readback.crc32 == payload->crc32 &&
                  pk_crc32((const uint8_t *)&readback, 764) == payload->crc32);
    pk_crypto_zeroize(&readback, sizeof(readback));
    if (!match) {
        return PK_ERR_FLASH_IO;
    }

    return PK_OK;
}

/* Helper: write State record to sector and verify readback */
static pk_err_t write_state_record(
    pk_storage_ctx_t *storage,
    uint8_t sector,
    uint32_t generation
) {
    uint32_t offset = (uint32_t)sector * PK_FLASH_SECTOR_SIZE;

    pk_err_t err = storage->platform->flash_erase_sector(storage->platform->ctx, offset);
    if (err != PK_OK) {
        return err;
    }

    pk_flash_state_record_t rec;
    rec.magic = PK_STORAGE_STATE_MAGIC;
    rec.version = PK_STORAGE_VERSION;
    rec.reserved = 0;
    rec.generation = generation;
    rec.state = storage->state;
    memset(rec.padding, 0xFF, sizeof(rec.padding));
    rec.crc32 = pk_crc32((const uint8_t *)&rec, 252);

    err = storage->platform->flash_program_page(
        storage->platform->ctx,
        offset,
        (const uint8_t *)&rec,
        sizeof(rec)
    );
    if (err != PK_OK) {
        pk_crypto_zeroize(&rec, sizeof(rec));
        return err;
    }

    pk_flash_state_record_t readback;
    err = storage->platform->flash_read(
        storage->platform->ctx,
        offset,
        (uint8_t *)&readback,
        sizeof(readback)
    );
    if (err != PK_OK) {
        pk_crypto_zeroize(&rec, sizeof(rec));
        pk_crypto_zeroize(&readback, sizeof(readback));
        return err;
    }
    bool match = (readback.magic == PK_STORAGE_STATE_MAGIC &&
                  readback.version == PK_STORAGE_VERSION &&
                  readback.generation == generation &&
                  readback.crc32 == rec.crc32 &&
                  pk_crc32((const uint8_t *)&readback, 252) == rec.crc32);
    pk_crypto_zeroize(&rec, sizeof(rec));
    pk_crypto_zeroize(&readback, sizeof(readback));
    if (!match) {
        return PK_ERR_FLASH_IO;
    }

    return PK_OK;
}

/* Helper: write counter page and verify readback */
static pk_err_t write_counter_page(
    pk_storage_ctx_t *storage,
    uint8_t sector,
    uint16_t slot_idx,
    uint32_t counter_val
) {
    uint32_t offset = (uint32_t)sector * PK_FLASH_SECTOR_SIZE + (uint32_t)slot_idx * PK_FLASH_PAGE_SIZE;

    pk_flash_counter_page_t page;
    page.magic = PK_STORAGE_CNT_MAGIC;
    page.counter_val = counter_val;
    memset(page.padding, 0xFF, sizeof(page.padding));
    page.crc32 = pk_crc32((const uint8_t *)&page, 252);

    pk_err_t err = storage->platform->flash_program_page(
        storage->platform->ctx,
        offset,
        (const uint8_t *)&page,
        sizeof(page)
    );
    if (err != PK_OK) {
        return err;
    }

    pk_flash_counter_page_t readback;
    err = storage->platform->flash_read(
        storage->platform->ctx,
        offset,
        (uint8_t *)&readback,
        sizeof(readback)
    );
    if (err != PK_OK) {
        return err;
    }
    if (readback.magic != PK_STORAGE_CNT_MAGIC ||
        readback.counter_val != counter_val ||
        readback.crc32 != page.crc32 ||
        pk_crc32((const uint8_t *)&readback, 252) != page.crc32) {
        return PK_ERR_FLASH_IO;
    }

    return PK_OK;
}

/* Helper: allocate a credential slot using wear-leveling across sectors */
static pk_err_t allocate_slot(pk_storage_ctx_t *storage, uint16_t *out_slot) {
    typedef struct {
        uint8_t empty_count;
        uint8_t tombstone_count;
        uint8_t active_count;
        int first_empty_slot;
    } sector_stat_t;

    sector_stat_t stats[PK_STORAGE_CRED_SECTOR_COUNT];

    for (uint32_t sec_idx = 0; sec_idx < PK_STORAGE_CRED_SECTOR_COUNT; sec_idx++) {
        stats[sec_idx].empty_count = 0;
        stats[sec_idx].tombstone_count = 0;
        stats[sec_idx].active_count = 0;
        stats[sec_idx].first_empty_slot = -1;

        for (uint32_t s = 0; s < PK_STORAGE_SLOTS_PER_SECTOR; s++) {
            uint16_t slot_idx = (uint16_t)(sec_idx * PK_STORAGE_SLOTS_PER_SECTOR + s);
            slot_state_t st = get_slot_state(storage, slot_idx, NULL);
            if (st == SLOT_STATE_EMPTY) {
                stats[sec_idx].empty_count++;
                if (stats[sec_idx].first_empty_slot == -1) {
                    stats[sec_idx].first_empty_slot = (int)s;
                }
            } else if (st == SLOT_STATE_ACTIVE) {
                stats[sec_idx].active_count++;
            } else {
                stats[sec_idx].tombstone_count++;
            }
        }
    }

    /* 1. Choose an empty slot from the sector with the lowest sector_erase_counts[sec] */
    int best_sec = -1;
    uint32_t min_erase = UINT32_MAX;
    for (uint32_t sec_idx = 0; sec_idx < PK_STORAGE_CRED_SECTOR_COUNT; sec_idx++) {
        if (stats[sec_idx].empty_count > 0) {
            if (best_sec == -1 || storage->sector_erase_counts[sec_idx] < min_erase) {
                best_sec = (int)sec_idx;
                min_erase = storage->sector_erase_counts[sec_idx];
            }
        }
    }

    if (best_sec != -1) {
        *out_slot = (uint16_t)(best_sec * PK_STORAGE_SLOTS_PER_SECTOR + stats[best_sec].first_empty_slot);
        return PK_OK;
    }

    /* 2. If no empty slots exist in any sector, find a sector where all 4 slots are tombstones */
    int all_tomb_sec = -1;
    uint32_t min_erase_tomb = UINT32_MAX;
    for (uint32_t sec_idx = 0; sec_idx < PK_STORAGE_CRED_SECTOR_COUNT; sec_idx++) {
        if (stats[sec_idx].tombstone_count == PK_STORAGE_SLOTS_PER_SECTOR) {
            if (all_tomb_sec == -1 || storage->sector_erase_counts[sec_idx] < min_erase_tomb) {
                all_tomb_sec = (int)sec_idx;
                min_erase_tomb = storage->sector_erase_counts[sec_idx];
            }
        }
    }

    if (all_tomb_sec != -1) {
        uint32_t sec_offset = (PK_STORAGE_CRED_FIRST_SECTOR + (uint32_t)all_tomb_sec) * PK_FLASH_SECTOR_SIZE;
        pk_err_t err = storage->platform->flash_erase_sector(storage->platform->ctx, sec_offset);
        if (err != PK_OK) {
            return err;
        }
        storage->sector_erase_counts[all_tomb_sec]++;
        *out_slot = (uint16_t)(all_tomb_sec * PK_STORAGE_SLOTS_PER_SECTOR);
        return PK_OK;
    }

    /* 3. Compact the sector with the most tombstones and lowest erase count */
    int compact_sec = -1;
    uint8_t max_tombs = 0;
    uint32_t compact_min_erase = UINT32_MAX;
    for (uint32_t sec_idx = 0; sec_idx < PK_STORAGE_CRED_SECTOR_COUNT; sec_idx++) {
        if (stats[sec_idx].tombstone_count > max_tombs) {
            max_tombs = stats[sec_idx].tombstone_count;
            compact_sec = (int)sec_idx;
            compact_min_erase = storage->sector_erase_counts[sec_idx];
        } else if (stats[sec_idx].tombstone_count == max_tombs && max_tombs > 0) {
            if (storage->sector_erase_counts[sec_idx] < compact_min_erase) {
                compact_sec = (int)sec_idx;
                compact_min_erase = storage->sector_erase_counts[sec_idx];
            }
        }
    }

    if (compact_sec == -1 || max_tombs == 0) {
        return PK_ERR_FULL;
    }

    /* Read active slots from compact_sec (at most 3 active slots since max_tombs >= 1) */
    pk_flash_cred_payload_t active_payloads[PK_STORAGE_SLOTS_PER_SECTOR];
    uint8_t num_active = 0;
    for (uint32_t s = 0; s < PK_STORAGE_SLOTS_PER_SECTOR; s++) {
        uint16_t slot_idx = (uint16_t)(compact_sec * PK_STORAGE_SLOTS_PER_SECTOR + s);
        if (get_slot_state(storage, slot_idx, &active_payloads[num_active]) == SLOT_STATE_ACTIVE) {
            num_active++;
        }
    }

    uint32_t sec_offset = (PK_STORAGE_CRED_FIRST_SECTOR + (uint32_t)compact_sec) * PK_FLASH_SECTOR_SIZE;
    pk_err_t err = storage->platform->flash_erase_sector(storage->platform->ctx, sec_offset);
    if (err != PK_OK) {
        for (uint8_t i = 0; i < num_active; i++) {
            pk_crypto_zeroize(&active_payloads[i], sizeof(active_payloads[i]));
        }
        return err;
    }
    storage->sector_erase_counts[compact_sec]++;

    /* Write back active slots */
    for (uint8_t i = 0; i < num_active; i++) {
        uint16_t relocated_slot = (uint16_t)(compact_sec * PK_STORAGE_SLOTS_PER_SECTOR + i);
        active_payloads[i].erase_count = storage->sector_erase_counts[compact_sec];
        active_payloads[i].crc32 = pk_crc32((const uint8_t *)&active_payloads[i], 764);
        err = write_cred_slot(storage, relocated_slot, &active_payloads[i]);
        pk_crypto_zeroize(&active_payloads[i], sizeof(active_payloads[i]));
        if (err != PK_OK) {
            return err;
        }
    }

    *out_slot = (uint16_t)(compact_sec * PK_STORAGE_SLOTS_PER_SECTOR + num_active);
    return PK_OK;
}

/*
 * Public API Implementations
 */

pk_err_t pk_storage_init(
    pk_storage_ctx_t *storage,
    const pk_platform_t *platform,
    pk_crypto_ctx_t *crypto
) {
    if (!storage || !platform || !crypto) {
        return PK_ERR_INVALID_ARG;
    }

    memset(storage, 0, sizeof(*storage));
    storage->platform = platform;
    storage->crypto = crypto;

    /* 1. Read Sector 0 and Sector 1 */
    pk_flash_state_record_t rec0;
    bool sec0_valid = false;
    if (platform->flash_read(platform->ctx, PK_STORAGE_STATE_SECTOR_A * PK_FLASH_SECTOR_SIZE, (uint8_t *)&rec0, sizeof(rec0)) == PK_OK) {
        if (rec0.magic == PK_STORAGE_STATE_MAGIC &&
            rec0.version == PK_STORAGE_VERSION &&
            rec0.crc32 == pk_crc32((const uint8_t *)&rec0, 252)) {
            sec0_valid = true;
        }
    }

    pk_flash_state_record_t rec1;
    bool sec1_valid = false;
    if (platform->flash_read(platform->ctx, PK_STORAGE_STATE_SECTOR_B * PK_FLASH_SECTOR_SIZE, (uint8_t *)&rec1, sizeof(rec1)) == PK_OK) {
        if (rec1.magic == PK_STORAGE_STATE_MAGIC &&
            rec1.version == PK_STORAGE_VERSION &&
            rec1.crc32 == pk_crc32((const uint8_t *)&rec1, 252)) {
            sec1_valid = true;
        }
    }

    if (!sec0_valid && !sec1_valid) {
        return pk_storage_factory_reset(storage);
    }

    if (sec0_valid && sec1_valid) {
        if (rec1.generation > rec0.generation) {
            storage->active_state_sector = PK_STORAGE_STATE_SECTOR_B;
            storage->state_generation = rec1.generation;
            storage->state = rec1.state;
        } else {
            storage->active_state_sector = PK_STORAGE_STATE_SECTOR_A;
            storage->state_generation = rec0.generation;
            storage->state = rec0.state;
        }
    } else if (sec0_valid) {
        storage->active_state_sector = PK_STORAGE_STATE_SECTOR_A;
        storage->state_generation = rec0.generation;
        storage->state = rec0.state;
    } else {
        storage->active_state_sector = PK_STORAGE_STATE_SECTOR_B;
        storage->state_generation = rec1.generation;
        storage->state = rec1.state;
    }

    /* 2. Scan Counter Sectors 2 & 3 */
    uint32_t max_counter = 0;
    bool found_counter = false;
    uint8_t newest_cnt_sec = PK_STORAGE_COUNTER_SECTOR_A;
    uint16_t newest_cnt_page = 0;

    uint8_t cnt_sectors[2] = { PK_STORAGE_COUNTER_SECTOR_A, PK_STORAGE_COUNTER_SECTOR_B };
    for (size_t s = 0; s < 2; s++) {
        uint8_t csec = cnt_sectors[s];
        for (uint16_t p = 0; p < 16; p++) {
            pk_flash_counter_page_t page;
            uint32_t offset = (uint32_t)csec * PK_FLASH_SECTOR_SIZE + (uint32_t)p * PK_FLASH_PAGE_SIZE;
            if (platform->flash_read(platform->ctx, offset, (uint8_t *)&page, sizeof(page)) != PK_OK) {
                break;
            }
            if (page.magic == PK_STORAGE_CNT_MAGIC &&
                page.crc32 == pk_crc32((const uint8_t *)&page, 252)) {
                if (!found_counter || page.counter_val > max_counter) {
                    max_counter = page.counter_val;
                    newest_cnt_sec = csec;
                    newest_cnt_page = p;
                    found_counter = true;
                }
            } else {
                break;
            }
        }
    }

    if (found_counter) {
        storage->active_counter_sector = newest_cnt_sec;
        storage->counter_slot_idx = newest_cnt_page + 1U;
        storage->sign_counter = (max_counter > storage->state.base_sign_counter)
            ? max_counter
            : storage->state.base_sign_counter;
    } else {
        storage->active_counter_sector = PK_STORAGE_COUNTER_SECTOR_A;
        storage->counter_slot_idx = 0U;
        storage->sign_counter = storage->state.base_sign_counter;
    }

    /* 3. Scan Credential Sectors 4..31 */
    storage->next_cred_seq = 0U;
    for (uint32_t sec_idx = 0; sec_idx < PK_STORAGE_CRED_SECTOR_COUNT; sec_idx++) {
        storage->sector_erase_counts[sec_idx] = 0U;
        for (uint32_t s = 0; s < PK_STORAGE_SLOTS_PER_SECTOR; s++) {
            uint16_t slot_idx = (uint16_t)(sec_idx * PK_STORAGE_SLOTS_PER_SECTOR + s);
            pk_flash_cred_payload_t payload;
            slot_state_t st = get_slot_state(storage, slot_idx, &payload);
            if (st == SLOT_STATE_ACTIVE || st == SLOT_STATE_TOMBSTONE) {
                if (payload.magic == PK_STORAGE_CRED_MAGIC &&
                    payload.crc32 == pk_crc32((const uint8_t *)&payload, 764)) {
                    if (payload.write_seq > storage->next_cred_seq) {
                        storage->next_cred_seq = payload.write_seq;
                    }
                    if (payload.erase_count > storage->sector_erase_counts[sec_idx]) {
                        storage->sector_erase_counts[sec_idx] = payload.erase_count;
                    }
                }
            }
            pk_crypto_zeroize(&payload, sizeof(payload));
        }
    }

    /* 4. Crash-consistency recovery: Deduplicate any duplicate active slots resulting from power loss */
    for (uint16_t i = 0; i < PK_STORAGE_TOTAL_SLOTS; i++) {
        pk_flash_cred_payload_t p1;
        if (get_slot_state(storage, i, &p1) != SLOT_STATE_ACTIVE) {
            pk_crypto_zeroize(&p1, sizeof(p1));
            continue;
        }
        for (uint16_t j = (uint16_t)(i + 1); j < PK_STORAGE_TOTAL_SLOTS; j++) {
            pk_flash_cred_payload_t p2;
            if (get_slot_state(storage, j, &p2) == SLOT_STATE_ACTIVE) {
                if (memcmp(p1.rp_id_hash, p2.rp_id_hash, 32) == 0 &&
                    p1.user_id_len == p2.user_id_len &&
                    (p1.user_id_len == 0 || memcmp(p1.user_id, p2.user_id, p1.user_id_len) == 0)) {
                    /* Duplicate active slots found! Tombstone the older slot */
                    if (p1.write_seq < p2.write_seq) {
                        (void)tombstone_slot(storage, i);
                        pk_crypto_zeroize(&p2, sizeof(p2));
                        break;
                    } else {
                        (void)tombstone_slot(storage, j);
                    }
                }
            }
            pk_crypto_zeroize(&p2, sizeof(p2));
        }
        pk_crypto_zeroize(&p1, sizeof(p1));
    }

    storage->initialized = true;
    return PK_OK;
}

pk_err_t pk_storage_factory_reset(pk_storage_ctx_t *storage) {
    if (!storage || !storage->platform || !storage->crypto) {
        return PK_ERR_INVALID_ARG;
    }

    /* 1. Generate fresh secrets */
    pk_err_t err = pk_crypto_random(storage->crypto, storage->state.master_secret, sizeof(storage->state.master_secret));
    if (err != PK_OK) return err;

    err = pk_crypto_random(storage->crypto, storage->state.cred_mac_key, sizeof(storage->state.cred_mac_key));
    if (err != PK_OK) return err;

    err = pk_crypto_random(storage->crypto, storage->state.attestation_seed, sizeof(storage->state.attestation_seed));
    if (err != PK_OK) return err;

    storage->state.pin_set = false;
    storage->state.pin_retries = PK_PIN_MAX_RETRIES;
    memset(storage->state.pin_salt, 0, sizeof(storage->state.pin_salt));
    memset(storage->state.pin_hash_Verifier, 0, sizeof(storage->state.pin_hash_Verifier));
    memset(storage->state.pin_raw_hash16, 0, sizeof(storage->state.pin_raw_hash16));
    storage->state.base_sign_counter = 0;

    storage->state_generation = 1U;
    storage->active_state_sector = PK_STORAGE_STATE_SECTOR_A;
    storage->sign_counter = 0;
    storage->active_counter_sector = PK_STORAGE_COUNTER_SECTOR_A;
    storage->counter_slot_idx = 0U;
    storage->next_cred_seq = 0U;

    /* 2. Write State Sector 0 and erase Sector 1 */
    err = write_state_record(storage, PK_STORAGE_STATE_SECTOR_A, storage->state_generation);
    if (err != PK_OK) return err;

    err = storage->platform->flash_erase_sector(
        storage->platform->ctx,
        (uint32_t)PK_STORAGE_STATE_SECTOR_B * PK_FLASH_SECTOR_SIZE
    );
    if (err != PK_OK) return err;

    /* 3. Erase Counter Sectors 2 & 3 */
    err = storage->platform->flash_erase_sector(
        storage->platform->ctx,
        (uint32_t)PK_STORAGE_COUNTER_SECTOR_A * PK_FLASH_SECTOR_SIZE
    );
    if (err != PK_OK) return err;

    err = storage->platform->flash_erase_sector(
        storage->platform->ctx,
        (uint32_t)PK_STORAGE_COUNTER_SECTOR_B * PK_FLASH_SECTOR_SIZE
    );
    if (err != PK_OK) return err;

    /* 4. Erase all credential sectors (4..31) */
    for (uint32_t i = 0; i < PK_STORAGE_CRED_SECTOR_COUNT; i++) {
        uint32_t sec = PK_STORAGE_CRED_FIRST_SECTOR + i;
        err = storage->platform->flash_erase_sector(
            storage->platform->ctx,
            sec * PK_FLASH_SECTOR_SIZE
        );
        if (err != PK_OK) return err;
        storage->sector_erase_counts[i] = 1U;
    }

    storage->initialized = true;
    return PK_OK;
}

pk_err_t pk_storage_save_state(pk_storage_ctx_t *storage) {
    if (!storage || !storage->platform || !storage->initialized) {
        return PK_ERR_INVALID_ARG;
    }

    uint8_t inactive_sec = 1U - storage->active_state_sector;
    uint32_t next_gen = storage->state_generation + 1U;

    pk_err_t err = write_state_record(storage, inactive_sec, next_gen);
    if (err != PK_OK) {
        return err;
    }

    storage->state_generation = next_gen;
    storage->active_state_sector = inactive_sec;
    return PK_OK;
}

pk_err_t pk_storage_next_sign_counter(pk_storage_ctx_t *storage, uint32_t *out_counter) {
    if (!storage || !storage->platform || !storage->initialized) {
        return PK_ERR_INVALID_ARG;
    }

    uint32_t next_counter = storage->sign_counter + 1U;
    uint8_t target_sec = storage->active_counter_sector;
    uint16_t target_slot = storage->counter_slot_idx;

    if (target_slot >= 16U) {
        uint8_t alt_sec = (storage->active_counter_sector == PK_STORAGE_COUNTER_SECTOR_A)
            ? PK_STORAGE_COUNTER_SECTOR_B
            : PK_STORAGE_COUNTER_SECTOR_A;

        pk_err_t err = storage->platform->flash_erase_sector(
            storage->platform->ctx,
            (uint32_t)alt_sec * PK_FLASH_SECTOR_SIZE
        );
        if (err != PK_OK) {
            return err;
        }

        target_sec = alt_sec;
        target_slot = 0U;
    }

    pk_err_t err = write_counter_page(
        storage,
        target_sec,
        target_slot,
        next_counter
    );
    if (err != PK_OK) {
        return err;
    }

    if (target_slot == 0U && target_sec != storage->active_counter_sector) {
        storage->active_counter_sector = target_sec;
        storage->state.base_sign_counter = next_counter;
        (void)pk_storage_save_state(storage);
    }

    storage->sign_counter = next_counter;
    storage->counter_slot_idx = target_slot + 1U;
    if (out_counter) {
        *out_counter = next_counter;
    }
    return PK_OK;
}

pk_err_t pk_storage_save_credential(
    pk_storage_ctx_t *storage,
    const pk_resident_cred_t *cred
) {
    if (!storage || !storage->platform || !storage->initialized || !cred) {
        return PK_ERR_INVALID_ARG;
    }
    if (cred->user_id_len > PK_USER_ID_MAX_LEN) {
        return PK_ERR_INVALID_ARG;
    }

    bool is_overwrite = false;
    size_t active_count = 0;

    for (uint16_t slot_idx = 0; slot_idx < PK_STORAGE_TOTAL_SLOTS; slot_idx++) {
        pk_flash_cred_payload_t p;
        if (get_slot_state(storage, slot_idx, &p) == SLOT_STATE_ACTIVE) {
            active_count++;
            if (!is_overwrite) {
                if (memcmp(p.rp_id_hash, cred->rp_id_hash, 32) == 0 &&
                    p.user_id_len == cred->user_id_len &&
                    (cred->user_id_len == 0 || memcmp(p.user_id, cred->user_id, cred->user_id_len) == 0)) {
                    is_overwrite = true;
                }
            }
        }
        pk_crypto_zeroize(&p, sizeof(p));
    }

    if (!is_overwrite && active_count >= PK_STORAGE_MAX_RESIDENT_CREDS) {
        return PK_ERR_FULL;
    }

    uint16_t new_slot_idx = 0;
    pk_err_t err = allocate_slot(storage, &new_slot_idx);
    if (err != PK_OK) {
        return err;
    }

    uint32_t sec_idx = new_slot_idx / PK_STORAGE_SLOTS_PER_SECTOR;
    pk_flash_cred_payload_t payload;
    memset(&payload, 0xFF, sizeof(payload));
    payload.magic = PK_STORAGE_CRED_MAGIC;
    payload.write_seq = ++storage->next_cred_seq;
    payload.erase_count = storage->sector_erase_counts[sec_idx];
    payload.use_count = cred->use_count;
    payload.cred_Provide_up_uv_flags = cred->cred_Provide_up_uv_flags;
    memcpy(payload.cred_id, cred->cred_id, PK_CRED_ID_RESIDENT_LEN);
    memcpy(payload.cred_random, cred->cred_random, 32);
    memcpy(payload.priv_key, cred->priv_key, PK_P256_PRIVKEY_LEN);
    payload.pub_key = cred->pub_key;
    memcpy(payload.rp_id_hash, cred->rp_id_hash, 32);
    memset(payload.rp_id, 0, sizeof(payload.rp_id));
    strncpy(payload.rp_id, cred->rp_id, sizeof(payload.rp_id) - 1);
    payload.user_id_len = cred->user_id_len;
    memset(payload.user_id, 0, sizeof(payload.user_id));
    if (cred->user_id_len > 0) {
        memcpy(payload.user_id, cred->user_id, cred->user_id_len);
    }
    memset(payload.user_name, 0, sizeof(payload.user_name));
    strncpy(payload.user_name, cred->user_name, sizeof(payload.user_name) - 1);
    memset(payload.user_display_name, 0, sizeof(payload.user_display_name));
    strncpy(payload.user_display_name, cred->user_display_name, sizeof(payload.user_display_name) - 1);
    payload.hmac_secret_enabled = cred->hmac_secret_enabled ? 1U : 0U;
    memset(payload.reserved, 0, sizeof(payload.reserved));
    memset(payload.padding, 0xFF, sizeof(payload.padding));
    payload.crc32 = pk_crc32((const uint8_t *)&payload, 764);

    err = write_cred_slot(storage, new_slot_idx, &payload);
    pk_crypto_zeroize(&payload, sizeof(payload));
    if (err != PK_OK) {
        return err;
    }

    /* Tombstone older active slot with matching (rp_id_hash, user_id) */
    for (uint16_t slot_idx = 0; slot_idx < PK_STORAGE_TOTAL_SLOTS; slot_idx++) {
        if (slot_idx == new_slot_idx) {
            continue;
        }
        pk_flash_cred_payload_t p;
        if (get_slot_state(storage, slot_idx, &p) == SLOT_STATE_ACTIVE) {
            if (memcmp(p.rp_id_hash, cred->rp_id_hash, 32) == 0 &&
                p.user_id_len == cred->user_id_len &&
                (cred->user_id_len == 0 || memcmp(p.user_id, cred->user_id, cred->user_id_len) == 0)) {
                (void)tombstone_slot(storage, slot_idx);
            }
        }
        pk_crypto_zeroize(&p, sizeof(p));
    }

    return PK_OK;
}

pk_err_t pk_storage_find_by_rp(
    pk_storage_ctx_t *storage,
    const uint8_t rp_id_hash[32],
    pk_resident_cred_t *out_creds,
    size_t max_creds,
    size_t *out_count
) {
    if (!storage || !storage->platform || !storage->initialized || !rp_id_hash || !out_count) {
        return PK_ERR_INVALID_ARG;
    }

    *out_count = 0;

    typedef struct {
        uint16_t slot_index;
        uint32_t write_seq;
    } cred_match_t;

    cred_match_t matches[PK_STORAGE_MAX_RESIDENT_CREDS];
    size_t match_count = 0;

    for (uint16_t slot_idx = 0; slot_idx < PK_STORAGE_TOTAL_SLOTS; slot_idx++) {
        pk_flash_cred_payload_t p;
        if (get_slot_state(storage, slot_idx, &p) == SLOT_STATE_ACTIVE) {
            if (memcmp(p.rp_id_hash, rp_id_hash, 32) == 0) {
                if (match_count < PK_STORAGE_MAX_RESIDENT_CREDS) {
                    matches[match_count].slot_index = slot_idx;
                    matches[match_count].write_seq = p.write_seq;
                    match_count++;
                }
            }
        }
        pk_crypto_zeroize(&p, sizeof(p));
    }

    /* Sort matches descending by write_seq (newest first) */
    for (size_t i = 1; i < match_count; i++) {
        cred_match_t key = matches[i];
        size_t j = i;
        while (j > 0 && matches[j - 1].write_seq < key.write_seq) {
            matches[j] = matches[j - 1];
            j--;
        }
        matches[j] = key;
    }

    size_t to_copy = (match_count < max_creds) ? match_count : max_creds;
    if (out_creds && to_copy > 0) {
        for (size_t i = 0; i < to_copy; i++) {
            pk_flash_cred_payload_t p;
            (void)get_slot_state(storage, matches[i].slot_index, &p);

            out_creds[i].active = true;
            out_creds[i].slot_index = matches[i].slot_index;
            out_creds[i].write_seq = p.write_seq;
            out_creds[i].erase_count = p.erase_count;
            out_creds[i].use_count = p.use_count;
            out_creds[i].cred_Provide_up_uv_flags = p.cred_Provide_up_uv_flags;
            memcpy(out_creds[i].cred_id, p.cred_id, PK_CRED_ID_RESIDENT_LEN);
            memcpy(out_creds[i].cred_random, p.cred_random, 32);
            memcpy(out_creds[i].priv_key, p.priv_key, PK_P256_PRIVKEY_LEN);
            out_creds[i].pub_key = p.pub_key;
            memcpy(out_creds[i].rp_id_hash, p.rp_id_hash, 32);
            memcpy(out_creds[i].rp_id, p.rp_id, PK_RP_ID_MAX_LEN);
            out_creds[i].rp_id[PK_RP_ID_MAX_LEN - 1] = '\0';
            out_creds[i].user_id_len = p.user_id_len;
            memcpy(out_creds[i].user_id, p.user_id, PK_USER_ID_MAX_LEN);
            memcpy(out_creds[i].user_name, p.user_name, PK_USER_NAME_MAX_LEN);
            out_creds[i].user_name[PK_USER_NAME_MAX_LEN - 1] = '\0';
            memcpy(out_creds[i].user_display_name, p.user_display_name, PK_USER_DISPLAY_MAX_LEN);
            out_creds[i].user_display_name[PK_USER_DISPLAY_MAX_LEN - 1] = '\0';
            out_creds[i].hmac_secret_enabled = (p.hmac_secret_enabled != 0);

            pk_crypto_zeroize(&p, sizeof(p));
        }
    }

    *out_count = out_creds ? to_copy : match_count;
    return PK_OK;
}

pk_err_t pk_storage_find_by_id(
    pk_storage_ctx_t *storage,
    const uint8_t rp_id_hash[32],
    const uint8_t *cred_id,
    size_t cred_id_len,
    pk_resident_cred_t *out_cred
) {
    if (!storage || !storage->platform || !storage->initialized || !cred_id || !out_cred) {
        return PK_ERR_INVALID_ARG;
    }
    if (cred_id_len != PK_CRED_ID_RESIDENT_LEN) {
        return PK_ERR_NOT_FOUND;
    }

    for (uint16_t slot_idx = 0; slot_idx < PK_STORAGE_TOTAL_SLOTS; slot_idx++) {
        pk_flash_cred_payload_t p;
        if (get_slot_state(storage, slot_idx, &p) == SLOT_STATE_ACTIVE) {
            if (memcmp(p.cred_id, cred_id, PK_CRED_ID_RESIDENT_LEN) == 0) {
                if (rp_id_hash == NULL || memcmp(p.rp_id_hash, rp_id_hash, 32) == 0) {
                    out_cred->active = true;
                    out_cred->slot_index = slot_idx;
                    out_cred->write_seq = p.write_seq;
                    out_cred->erase_count = p.erase_count;
                    out_cred->use_count = p.use_count;
                    out_cred->cred_Provide_up_uv_flags = p.cred_Provide_up_uv_flags;
                    memcpy(out_cred->cred_id, p.cred_id, PK_CRED_ID_RESIDENT_LEN);
                    memcpy(out_cred->cred_random, p.cred_random, 32);
                    memcpy(out_cred->priv_key, p.priv_key, PK_P256_PRIVKEY_LEN);
                    out_cred->pub_key = p.pub_key;
                    memcpy(out_cred->rp_id_hash, p.rp_id_hash, 32);
                    memcpy(out_cred->rp_id, p.rp_id, PK_RP_ID_MAX_LEN);
                    out_cred->rp_id[PK_RP_ID_MAX_LEN - 1] = '\0';
                    out_cred->user_id_len = p.user_id_len;
                    memcpy(out_cred->user_id, p.user_id, PK_USER_ID_MAX_LEN);
                    memcpy(out_cred->user_name, p.user_name, PK_USER_NAME_MAX_LEN);
                    out_cred->user_name[PK_USER_NAME_MAX_LEN - 1] = '\0';
                    memcpy(out_cred->user_display_name, p.user_display_name, PK_USER_DISPLAY_MAX_LEN);
                    out_cred->user_display_name[PK_USER_DISPLAY_MAX_LEN - 1] = '\0';
                    out_cred->hmac_secret_enabled = (p.hmac_secret_enabled != 0);

                    pk_crypto_zeroize(&p, sizeof(p));
                    return PK_OK;
                }
            }
        }
        pk_crypto_zeroize(&p, sizeof(p));
    }

    return PK_ERR_NOT_FOUND;
}

pk_err_t pk_storage_delete_by_id(
    pk_storage_ctx_t *storage,
    const uint8_t *cred_id,
    size_t cred_id_len
) {
    if (!storage || !storage->platform || !storage->initialized || !cred_id) {
        return PK_ERR_INVALID_ARG;
    }
    if (cred_id_len != PK_CRED_ID_RESIDENT_LEN) {
        return PK_ERR_NOT_FOUND;
    }

    for (uint16_t slot_idx = 0; slot_idx < PK_STORAGE_TOTAL_SLOTS; slot_idx++) {
        pk_flash_cred_payload_t p;
        if (get_slot_state(storage, slot_idx, &p) == SLOT_STATE_ACTIVE) {
            if (memcmp(p.cred_id, cred_id, PK_CRED_ID_RESIDENT_LEN) == 0) {
                pk_crypto_zeroize(&p, sizeof(p));
                return tombstone_slot(storage, slot_idx);
            }
        }
        pk_crypto_zeroize(&p, sizeof(p));
    }

    return PK_ERR_NOT_FOUND;
}

pk_err_t pk_storage_get_stats(
    pk_storage_ctx_t *storage,
    size_t *out_active_creds,
    size_t *out_free_creds,
    size_t *out_rp_count
) {
    if (!storage || !storage->platform || !storage->initialized) {
        return PK_ERR_INVALID_ARG;
    }

    size_t active_count = 0;
    uint8_t rp_hashes[PK_STORAGE_MAX_RESIDENT_CREDS][32];
    size_t rp_count = 0;

    for (uint16_t slot_idx = 0; slot_idx < PK_STORAGE_TOTAL_SLOTS; slot_idx++) {
        pk_flash_cred_payload_t p;
        if (get_slot_state(storage, slot_idx, &p) == SLOT_STATE_ACTIVE) {
            active_count++;

            bool found_rp = false;
            for (size_t r = 0; r < rp_count; r++) {
                if (memcmp(rp_hashes[r], p.rp_id_hash, 32) == 0) {
                    found_rp = true;
                    break;
                }
            }
            if (!found_rp && rp_count < PK_STORAGE_MAX_RESIDENT_CREDS) {
                memcpy(rp_hashes[rp_count], p.rp_id_hash, 32);
                rp_count++;
            }
        }
        pk_crypto_zeroize(&p, sizeof(p));
    }

    if (out_active_creds) {
        *out_active_creds = active_count;
    }
    if (out_free_creds) {
        *out_free_creds = (active_count < PK_STORAGE_MAX_RESIDENT_CREDS)
            ? (PK_STORAGE_MAX_RESIDENT_CREDS - active_count)
            : 0;
    }
    if (out_rp_count) {
        *out_rp_count = rp_count;
    }
    return PK_OK;
}

pk_err_t pk_storage_list_rps(
    pk_storage_ctx_t *storage,
    pk_rp_summary_t *out_rps,
    size_t max_rps,
    size_t *out_count
) {
    if (!storage || !storage->platform || !storage->initialized || !out_count) {
        return PK_ERR_INVALID_ARG;
    }

    *out_count = 0;

    pk_rp_summary_t rps[PK_STORAGE_MAX_RESIDENT_CREDS];
    size_t rp_count = 0;

    for (uint16_t slot_idx = 0; slot_idx < PK_STORAGE_TOTAL_SLOTS; slot_idx++) {
        pk_flash_cred_payload_t p;
        if (get_slot_state(storage, slot_idx, &p) == SLOT_STATE_ACTIVE) {
            bool found_rp = false;
            for (size_t r = 0; r < rp_count; r++) {
                if (memcmp(rps[r].rp_id_hash, p.rp_id_hash, 32) == 0) {
                    found_rp = true;
                    break;
                }
            }
            if (!found_rp && rp_count < PK_STORAGE_MAX_RESIDENT_CREDS) {
                memcpy(rps[rp_count].rp_id_hash, p.rp_id_hash, 32);
                memcpy(rps[rp_count].rp_id, p.rp_id, PK_RP_ID_MAX_LEN);
                rps[rp_count].rp_id[PK_RP_ID_MAX_LEN - 1] = '\0';
                rp_count++;
            }
        }
        pk_crypto_zeroize(&p, sizeof(p));
    }

    size_t to_copy = (rp_count < max_rps) ? rp_count : max_rps;
    if (out_rps && to_copy > 0) {
        for (size_t i = 0; i < to_copy; i++) {
            out_rps[i] = rps[i];
        }
    }

    *out_count = out_rps ? to_copy : rp_count;
    return PK_OK;
}
