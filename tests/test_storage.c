#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "passkey/storage.h"
#include "passkey/crypto.h"
#include "passkey/status.h"
#include "passkey/config.h"
#include "mock_platform.h"

#define TEST_PASS_MSG(test_name) printf("  [PASS] %s\n", (test_name))
#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "  [FAIL] %s:%d: %s (%s)\n", __FILE__, __LINE__, msg, #cond); \
        return 1; \
    } \
} while (0)

static void helper_fill_cred(
    pk_resident_cred_t *c,
    const char *rp_id,
    const uint8_t *user_id,
    uint8_t user_id_len,
    const char *user_name,
    const char *user_display_name,
    uint8_t id_tag
) {
    memset(c, 0, sizeof(*c));
    c->active = true;
    strncpy(c->rp_id, rp_id, sizeof(c->rp_id) - 1);
    pk_crypto_sha256((const uint8_t *)rp_id, strlen(rp_id), c->rp_id_hash);

    c->user_id_len = user_id_len;
    if (user_id_len > 0 && user_id) {
        memcpy(c->user_id, user_id, user_id_len);
    }
    strncpy(c->user_name, user_name, sizeof(c->user_name) - 1);
    strncpy(c->user_display_name, user_display_name, sizeof(c->user_display_name) - 1);

    /* Generate unique credential ID and mock keys */
    memset(c->cred_id, id_tag, sizeof(c->cred_id));
    c->cred_id[0] = id_tag;
    c->cred_id[PK_CRED_ID_RESIDENT_LEN - 1] = (uint8_t)(~id_tag);

    memset(c->cred_random, id_tag, 32);
    memset(c->priv_key, id_tag + 1, PK_P256_PRIVKEY_LEN);
    memset(c->pub_key.x, id_tag + 2, 32);
    memset(c->pub_key.y, id_tag + 3, 32);
}

/* 1. Test fresh format and initialization, verifying random root keys are generated */
static int test_fresh_format_and_init(
    pk_mock_platform_state_t *mock,
    pk_platform_t *platform,
    pk_crypto_ctx_t *crypto,
    pk_storage_ctx_t *storage
) {
    /* Flash is uninitialized (all 0xFF) */
    memset(mock->flash, 0xFF, sizeof(mock->flash));

    pk_err_t err = pk_storage_init(storage, platform, crypto);
    TEST_ASSERT(err == PK_OK, "pk_storage_init on fresh flash failed");
    TEST_ASSERT(storage->initialized == true, "Storage should be marked initialized");
    TEST_ASSERT(storage->state_generation >= 1, "Initial state generation must be >= 1");
    TEST_ASSERT(storage->sign_counter == 0, "Initial signature counter must be 0");

    /* Verify root keys are not all zeroes and not all 0xFF */
    uint8_t zeros[32] = { 0 };
    uint8_t ffs[32];
    memset(ffs, 0xFF, sizeof(ffs));

    TEST_ASSERT(memcmp(storage->state.master_secret, zeros, 32) != 0, "master_secret cannot be all zeros");
    TEST_ASSERT(memcmp(storage->state.master_secret, ffs, 32) != 0, "master_secret cannot be all 0xFF");

    TEST_ASSERT(memcmp(storage->state.cred_mac_key, zeros, 32) != 0, "cred_mac_key cannot be all zeros");
    TEST_ASSERT(memcmp(storage->state.cred_mac_key, ffs, 32) != 0, "cred_mac_key cannot be all 0xFF");

    TEST_ASSERT(memcmp(storage->state.attestation_seed, zeros, 32) != 0, "attestation_seed cannot be all zeros");
    TEST_ASSERT(memcmp(storage->state.attestation_seed, ffs, 32) != 0, "attestation_seed cannot be all 0xFF");

    TEST_PASS_MSG("Fresh format and initialization with random root keys");
    return 0;
}

/* 2. Test reboot persistence: re-run pk_storage_init on same flash buffer */
static int test_reboot_persistence(
    pk_platform_t *platform,
    pk_crypto_ctx_t *crypto,
    pk_storage_ctx_t *storage
) {
    uint8_t saved_master_secret[32];
    uint8_t saved_cred_mac_key[32];
    uint32_t saved_generation = storage->state_generation;

    memcpy(saved_master_secret, storage->state.master_secret, 32);
    memcpy(saved_cred_mac_key, storage->state.cred_mac_key, 32);

    /* Simulate power cycle: zero context struct and reinitialize */
    pk_storage_ctx_t rebooted_storage;
    memset(&rebooted_storage, 0, sizeof(rebooted_storage));

    pk_err_t err = pk_storage_init(&rebooted_storage, platform, crypto);
    TEST_ASSERT(err == PK_OK, "pk_storage_init after simulated reboot failed");
    TEST_ASSERT(rebooted_storage.initialized == true, "Storage should be initialized after reboot");
    TEST_ASSERT(rebooted_storage.state_generation == saved_generation, "state_generation must persist");
    TEST_ASSERT(memcmp(rebooted_storage.state.master_secret, saved_master_secret, 32) == 0,
                "master_secret must persist across reboot");
    TEST_ASSERT(memcmp(rebooted_storage.state.cred_mac_key, saved_cred_mac_key, 32) == 0,
                "cred_mac_key must persist across reboot");

    *storage = rebooted_storage;
    TEST_PASS_MSG("Reboot persistence of root secrets and state generation");
    return 0;
}

/* 3. Test A/B state journaling recovery: corrupt active state sector's CRC and verify rollback */
static int test_ab_journaling_recovery(
    pk_mock_platform_state_t *mock,
    pk_platform_t *platform,
    pk_crypto_ctx_t *crypto,
    pk_storage_ctx_t *storage
) {
    /* Current state is valid in active_state_sector. Save updated state to commit to alternate sector. */
    storage->state.pin_set = true;
    storage->state.pin_retries = 5;
    uint32_t gen_before = storage->state_generation;

    pk_err_t err = pk_storage_save_state(storage);
    TEST_ASSERT(err == PK_OK, "pk_storage_save_state failed");
    TEST_ASSERT(storage->state_generation == gen_before + 1, "state_generation must increment on save");

    uint8_t active_sec = storage->active_state_sector;

    /* Now Sector `active_sec` has the higher generation.
     * The other sector `1 - active_sec` has generation `gen_before`.
     * Let's corrupt the active state sector's CRC in mock flash!
     * State record Page 0 has CRC at offset 252 (or within bytes 0..255).
     */
    uint32_t active_sec_offset = (uint32_t)active_sec * PK_FLASH_SECTOR_SIZE;
    mock->flash[active_sec_offset + 252] ^= 0xFF;
    mock->flash[active_sec_offset + 253] ^= 0xAA;

    /* Reboot storage: should detect corrupt CRC in active sector and fall back to the alternate sector */
    pk_storage_ctx_t recovered_storage;
    memset(&recovered_storage, 0, sizeof(recovered_storage));

    err = pk_storage_init(&recovered_storage, platform, crypto);
    TEST_ASSERT(err == PK_OK, "pk_storage_init should succeed by falling back to alternate valid sector");
    TEST_ASSERT(recovered_storage.initialized == true, "Storage should be initialized after recovery");
    TEST_ASSERT(recovered_storage.active_state_sector == (1U - active_sec),
                "Active state sector should have fallen back to previous valid sector");
    TEST_ASSERT(recovered_storage.state_generation == gen_before,
                "State generation should be rolled back to previous valid generation");

    *storage = recovered_storage;
    TEST_PASS_MSG("A/B state journaling automatic fallback on CRC corruption");
    return 0;
}

/* 4. Test monotonic signature counter persistence across 40 increments and sector rollovers */
static int test_sign_counter_persistence(
    pk_platform_t *platform,
    pk_crypto_ctx_t *crypto,
    pk_storage_ctx_t *storage
) {
    uint32_t start_counter = storage->sign_counter;

    for (uint32_t i = 1; i <= 40; ++i) {
        uint32_t out_counter = 0;
        pk_err_t err = pk_storage_next_sign_counter(storage, &out_counter);
        TEST_ASSERT(err == PK_OK, "pk_storage_next_sign_counter failed");
        TEST_ASSERT(out_counter == start_counter + i, "Counter value must increment by 1");
        TEST_ASSERT(storage->sign_counter == out_counter, "storage->sign_counter must match out_counter");

        /* Simulate power cycles at key milestones (including sector rollovers at 16, 32) */
        if (i == 10 || i == 18 || i == 34) {
            pk_storage_ctx_t reboot_storage;
            memset(&reboot_storage, 0, sizeof(reboot_storage));

            err = pk_storage_init(&reboot_storage, platform, crypto);
            TEST_ASSERT(err == PK_OK, "pk_storage_init during counter stress test failed");
            TEST_ASSERT(reboot_storage.sign_counter == out_counter,
                        "Counter must match latest persisted counter after reboot");

            *storage = reboot_storage;
        }
    }

    /* Final reboot check at counter 40 */
    pk_storage_ctx_t final_storage;
    memset(&final_storage, 0, sizeof(final_storage));
    pk_err_t err = pk_storage_init(&final_storage, platform, crypto);
    TEST_ASSERT(err == PK_OK, "Final pk_storage_init failed");
    TEST_ASSERT(final_storage.sign_counter == start_counter + 40,
                "Final recovered sign_counter must match start + 40");

    *storage = final_storage;
    TEST_PASS_MSG("Monotonic signature counter across 40 increments, sector rollovers, and reboots");
    return 0;
}

/* 5. Test resident credential CRUD: create, newest-first find, find_by_id, overwrite, delete */
static int test_resident_credential_crud(pk_storage_ctx_t *storage)
{
    /* RP 1: example.com */
    const uint8_t user_alice[4] = { 0x01, 0x02, 0x03, 0x04 };
    const uint8_t user_bob[4]   = { 0x05, 0x06, 0x07, 0x08 };

    pk_resident_cred_t cred_alice;
    helper_fill_cred(&cred_alice, "example.com", user_alice, sizeof(user_alice), "alice", "Alice Wonder", 0xA1);

    pk_resident_cred_t cred_bob;
    helper_fill_cred(&cred_bob, "example.com", user_bob, sizeof(user_bob), "bob", "Bob Builder", 0xB2);

    /* RP 2: github.com */
    const uint8_t user_carol[4] = { 0x09, 0x0A, 0x0B, 0x0C };
    pk_resident_cred_t cred_carol;
    helper_fill_cred(&cred_carol, "github.com", user_carol, sizeof(user_carol), "carol", "Carol Developer", 0xC3);

    /* Save credentials: alice first, then bob, then carol */
    pk_err_t err = pk_storage_save_credential(storage, &cred_alice);
    TEST_ASSERT(err == PK_OK, "Save cred_alice failed");

    err = pk_storage_save_credential(storage, &cred_bob);
    TEST_ASSERT(err == PK_OK, "Save cred_bob failed");

    err = pk_storage_save_credential(storage, &cred_carol);
    TEST_ASSERT(err == PK_OK, "Save cred_carol failed");

    /* Test pk_storage_find_by_rp with newest-first ordering for example.com */
    uint8_t rp_example_hash[32];
    pk_crypto_sha256((const uint8_t *)"example.com", 11, rp_example_hash);

    pk_resident_cred_t out_creds[4];
    size_t out_count = 0;
    err = pk_storage_find_by_rp(storage, rp_example_hash, out_creds, 4, &out_count);
    TEST_ASSERT(err == PK_OK, "pk_storage_find_by_rp failed");
    TEST_ASSERT(out_count == 2, "example.com should have exactly 2 credentials");
    /* Newest first: Bob was written after Alice */
    TEST_ASSERT(strcmp(out_creds[0].user_name, "bob") == 0, "Newest credential must come first (bob)");
    TEST_ASSERT(strcmp(out_creds[1].user_name, "alice") == 0, "Older credential must come second (alice)");
    TEST_ASSERT(out_creds[0].write_seq > out_creds[1].write_seq, "write_seq must be strictly descending");

    /* Test pk_storage_find_by_id */
    pk_resident_cred_t found_alice;
    err = pk_storage_find_by_id(storage, rp_example_hash, cred_alice.cred_id, sizeof(cred_alice.cred_id), &found_alice);
    TEST_ASSERT(err == PK_OK, "pk_storage_find_by_id for alice failed");
    TEST_ASSERT(strcmp(found_alice.user_name, "alice") == 0, "Found credential user_name mismatch");

    /* Non-existent ID returns PK_ERR_NOT_FOUND */
    uint8_t bogus_id[PK_CRED_ID_RESIDENT_LEN];
    memset(bogus_id, 0xEE, sizeof(bogus_id));
    err = pk_storage_find_by_id(storage, rp_example_hash, bogus_id, sizeof(bogus_id), &found_alice);
    TEST_ASSERT(err == PK_ERR_NOT_FOUND, "pk_storage_find_by_id with bogus ID must return PK_ERR_NOT_FOUND");

    /* Credential overwrite test: save updated alice with same (rp_id_hash, user_id) */
    size_t active_before = 0, free_before = 0, rp_count_before = 0;
    pk_storage_get_stats(storage, &active_before, &free_before, &rp_count_before);

    pk_resident_cred_t cred_alice_updated;
    helper_fill_cred(&cred_alice_updated, "example.com", user_alice, sizeof(user_alice), "alice", "Alice Updated", 0xA2);

    err = pk_storage_save_credential(storage, &cred_alice_updated);
    TEST_ASSERT(err == PK_OK, "Credential overwrite save failed");

    size_t active_after = 0, free_after = 0, rp_count_after = 0;
    pk_storage_get_stats(storage, &active_after, &free_after, &rp_count_after);

    TEST_ASSERT(active_after == active_before, "Overwriting credential must NOT increase active credential count");
    /* Old alice cred_id should be tombstoned / not found */
    err = pk_storage_find_by_id(storage, rp_example_hash, cred_alice.cred_id, sizeof(cred_alice.cred_id), &found_alice);
    TEST_ASSERT(err == PK_ERR_NOT_FOUND, "Old credential ID must be tombstoned and not found");

    /* New alice cred_id should be active */
    err = pk_storage_find_by_id(storage, rp_example_hash, cred_alice_updated.cred_id, sizeof(cred_alice_updated.cred_id), &found_alice);
    TEST_ASSERT(err == PK_OK, "New overwritten credential ID must be active");
    TEST_ASSERT(strcmp(found_alice.user_display_name, "Alice Updated") == 0, "User display name should be updated");

    /* Delete Bob by ID */
    err = pk_storage_delete_by_id(storage, cred_bob.cred_id, sizeof(cred_bob.cred_id));
    TEST_ASSERT(err == PK_OK, "pk_storage_delete_by_id for bob failed");

    /* Verify Bob is gone */
    err = pk_storage_find_by_id(storage, rp_example_hash, cred_bob.cred_id, sizeof(cred_bob.cred_id), &found_alice);
    TEST_ASSERT(err == PK_ERR_NOT_FOUND, "Deleted Bob must return PK_ERR_NOT_FOUND");

    /* Verify RP query now only returns Alice */
    err = pk_storage_find_by_rp(storage, rp_example_hash, out_creds, 4, &out_count);
    TEST_ASSERT(err == PK_OK, "Find after delete failed");
    TEST_ASSERT(out_count == 1, "Only 1 credential should remain for example.com");
    TEST_ASSERT(strcmp(out_creds[0].user_display_name, "Alice Updated") == 0, "Remaining credential should be Alice");

    TEST_PASS_MSG("Resident credential CRUD (create, newest-first, overwrite, delete)");
    return 0;
}

/* 6. Test mid-write power-loss recovery using mock fault injection */
static int test_mid_write_recovery(
    pk_mock_platform_state_t *mock,
    pk_platform_t *platform,
    pk_crypto_ctx_t *crypto,
    pk_storage_ctx_t *storage
) {
    /* Verify current credential state */
    uint8_t rp_example_hash[32];
    pk_crypto_sha256((const uint8_t *)"example.com", 11, rp_example_hash);

    pk_resident_cred_t before_creds[4];
    size_t count_before = 0;
    pk_storage_find_by_rp(storage, rp_example_hash, before_creds, 4, &count_before);
    TEST_ASSERT(count_before >= 1, "Should have at least 1 credential before fault injection");

    /* Prepare a new credential to save */
    const uint8_t user_fault[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    pk_resident_cred_t cred_fail;
    helper_fill_cred(&cred_fail, "example.com", user_fault, sizeof(user_fault), "fail_user", "Fail User", 0xF0);

    /* Configure mock platform to fail flash programming after 1 page (slot needs 3 pages) */
    mock->fail_after_pages = true;
    mock->pages_remaining_before_fail = 1;

    pk_err_t err = pk_storage_save_credential(storage, &cred_fail);
    TEST_ASSERT(err != PK_OK, "pk_storage_save_credential should fail when flash write fails");

    /* Clear fault injection hook */
    mock->fail_after_pages = false;
    mock->pages_remaining_before_fail = 0;

    /* Simulate power cycle and reboot */
    pk_storage_ctx_t reboot_storage;
    memset(&reboot_storage, 0, sizeof(reboot_storage));

    err = pk_storage_init(&reboot_storage, platform, crypto);
    TEST_ASSERT(err == PK_OK, "pk_storage_init after power failure should succeed");
    TEST_ASSERT(reboot_storage.initialized == true, "Storage should reinitialize cleanly");

    /* Verify that the partially-written slot was ignored */
    pk_resident_cred_t out_cred;
    err = pk_storage_find_by_id(&reboot_storage, rp_example_hash, cred_fail.cred_id, sizeof(cred_fail.cred_id), &out_cred);
    TEST_ASSERT(err == PK_ERR_NOT_FOUND, "Half-written credential must NOT be present");

    /* Verify that pre-existing valid credentials remain intact */
    pk_resident_cred_t after_creds[4];
    size_t count_after = 0;
    err = pk_storage_find_by_rp(&reboot_storage, rp_example_hash, after_creds, 4, &count_after);
    TEST_ASSERT(err == PK_OK, "pk_storage_find_by_rp after reboot failed");
    TEST_ASSERT(count_after == count_before, "Pre-existing credentials must remain completely intact");

    *storage = reboot_storage;
    TEST_PASS_MSG("Mid-write power-loss recovery and flash integrity");
    return 0;
}

/* 7. Test flash wear-leveling across sectors and pk_storage_factory_reset */
static int test_wear_leveling_and_factory_reset(
    pk_storage_ctx_t *storage
) {
    /* Verify wear-leveling: allocate credentials across multiple sectors */
    for (uint32_t i = 0; i < 8; ++i) {
        char rp_buf[32];
        snprintf(rp_buf, sizeof(rp_buf), "rp%u.org", (unsigned)i);
        uint8_t u_id[4] = { (uint8_t)i, (uint8_t)(i + 1), (uint8_t)(i + 2), (uint8_t)(i + 3) };
        pk_resident_cred_t c;
        helper_fill_cred(&c, rp_buf, u_id, 4, "user", "User", (uint8_t)(0x10 + i));
        pk_err_t err = pk_storage_save_credential(storage, &c);
        TEST_ASSERT(err == PK_OK, "Wear-leveling credential save failed");
    }

    size_t active_creds = 0, free_creds = 0, rp_count = 0;
    pk_err_t err = pk_storage_get_stats(storage, &active_creds, &free_creds, &rp_count);
    TEST_ASSERT(err == PK_OK, "pk_storage_get_stats failed");
    TEST_ASSERT(active_creds >= 8, "Active credentials should be >= 8");
    TEST_ASSERT(rp_count >= 8, "Distinct RP count should be >= 8");

    /* Test RP listing */
    pk_rp_summary_t rps[16];
    size_t enumerated_rps = 0;
    err = pk_storage_list_rps(storage, rps, 16, &enumerated_rps);
    TEST_ASSERT(err == PK_OK, "pk_storage_list_rps failed");
    TEST_ASSERT(enumerated_rps == rp_count, "Enumerated RP count should match get_stats rp_count");

    /* Factory Reset: wipes all credentials, resets PIN, generates new root keys */
    uint8_t old_master[32];
    memcpy(old_master, storage->state.master_secret, 32);

    err = pk_storage_factory_reset(storage);
    TEST_ASSERT(err == PK_OK, "pk_storage_factory_reset failed");
    TEST_ASSERT(storage->sign_counter == 0, "Counter must reset to 0");
    TEST_ASSERT(memcmp(storage->state.master_secret, old_master, 32) != 0,
                "Factory reset must regenerate root master_secret");

    /* Verify all credentials are wiped */
    size_t post_reset_active = 0, post_reset_free = 0, post_reset_rps = 0;
    pk_storage_get_stats(storage, &post_reset_active, &post_reset_free, &post_reset_rps);
    TEST_ASSERT(post_reset_active == 0, "Active credentials must be 0 after factory reset");
    TEST_ASSERT(post_reset_rps == 0, "RP count must be 0 after factory reset");

    TEST_PASS_MSG("Flash wear-leveling and factory reset");
    return 0;
}

int main(void)
{
    printf("=== Running storage unit tests ===\n");

    pk_mock_platform_state_t mock;
    pk_platform_t platform;
    pk_mock_platform_init(&mock, &platform);

    pk_crypto_ctx_t crypto;
    pk_err_t err = pk_crypto_init(&crypto, &platform);
    if (err != PK_OK) {
        fprintf(stderr, "pk_crypto_init failed: %d\n", (int)err);
        return 1;
    }

    pk_storage_ctx_t storage;
    memset(&storage, 0, sizeof(storage));

    if (test_fresh_format_and_init(&mock, &platform, &crypto, &storage) != 0) return 1;
    if (test_reboot_persistence(&platform, &crypto, &storage) != 0) return 1;
    if (test_ab_journaling_recovery(&mock, &platform, &crypto, &storage) != 0) return 1;
    if (test_sign_counter_persistence(&platform, &crypto, &storage) != 0) return 1;
    if (test_resident_credential_crud(&storage) != 0) return 1;
    if (test_mid_write_recovery(&mock, &platform, &crypto, &storage) != 0) return 1;
    if (test_wear_leveling_and_factory_reset(&storage) != 0) return 1;

    printf("\n[PASS] All storage unit tests passed successfully!\n");
    return 0;
}
