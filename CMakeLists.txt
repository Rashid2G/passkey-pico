cmake_minimum_required(VERSION 3.16)

option(PICO_PASSKEY_HOST_TESTS "Build native host unit & integration tests instead of RP2040 UF2 firmware" OFF)

if(NOT PICO_PASSKEY_HOST_TESTS)
    include(pico_sdk_import.cmake)
endif()

project(pico_passkey C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)

set(PASSKEY_CORE_SOURCES
    src/status.c
    src/cbor.c
    src/crypto.c
    src/storage.c
    src/pin.c
    src/ctap2.c
    src/ctaphid.c
    src/usb_descriptors.c
    src/usb_hid.c
)

if(PICO_PASSKEY_HOST_TESTS)
    enable_testing()

    add_compile_options(-Wall -Wextra -Wpedantic)

    find_path(MBEDTLS_INCLUDE_DIR
        NAMES mbedtls/ecdsa.h
        PATH_SUFFIXES mbedtls3
        PATHS /usr/include /usr/local/include
        REQUIRED
    )
    find_library(MBEDCRYPTO_LIB
        NAMES mbedcrypto
        PATH_SUFFIXES mbedtls3
        PATHS /usr/lib /usr/local/lib
        REQUIRED
    )

    add_library(passkey_core STATIC
        ${PASSKEY_CORE_SOURCES}
        tests/mock_platform.c
    )
    target_include_directories(passkey_core PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
        ${MBEDTLS_INCLUDE_DIR}
    )
    target_link_libraries(passkey_core PUBLIC ${MBEDCRYPTO_LIB})

    function(add_passkey_test TEST_NAME TEST_SRC)
        add_executable(${TEST_NAME} ${TEST_SRC})
        target_link_libraries(${TEST_NAME} PRIVATE passkey_core)
        add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    endfunction()

    add_passkey_test(test_crypto tests/test_crypto.c)
    add_passkey_test(test_storage tests/test_storage.c)
    add_passkey_test(test_ctaphid tests/test_ctaphid.c)
    add_passkey_test(test_ctap2 tests/test_ctap2.c)
    add_passkey_test(test_webauthn_e2e tests/test_webauthn_e2e.c)
else()
    pico_sdk_init()

    set(MBEDTLS_ROOT "${PICO_SDK_PATH}/lib/mbedtls")
    set(MBEDTLS_CRYPTO_SOURCES
        ${MBEDTLS_ROOT}/library/aes.c
        ${MBEDTLS_ROOT}/library/asn1parse.c
        ${MBEDTLS_ROOT}/library/asn1write.c
        ${MBEDTLS_ROOT}/library/bignum.c
        ${MBEDTLS_ROOT}/library/cipher.c
        ${MBEDTLS_ROOT}/library/cipher_wrap.c
        ${MBEDTLS_ROOT}/library/constant_time.c
        ${MBEDTLS_ROOT}/library/ctr_drbg.c
        ${MBEDTLS_ROOT}/library/ecdh.c
        ${MBEDTLS_ROOT}/library/ecdsa.c
        ${MBEDTLS_ROOT}/library/ecp.c
        ${MBEDTLS_ROOT}/library/ecp_curves.c
        ${MBEDTLS_ROOT}/library/entropy.c
        ${MBEDTLS_ROOT}/library/entropy_poll.c
        ${MBEDTLS_ROOT}/library/hkdf.c
        ${MBEDTLS_ROOT}/library/md.c
        ${MBEDTLS_ROOT}/library/oid.c
        ${MBEDTLS_ROOT}/library/platform.c
        ${MBEDTLS_ROOT}/library/platform_util.c
        ${MBEDTLS_ROOT}/library/sha256.c
    )

    add_executable(pico_passkey
        ${PASSKEY_CORE_SOURCES}
        src/platform_pico.c
        src/main.c
        ${MBEDTLS_CRYPTO_SOURCES}
    )

    target_compile_definitions(pico_passkey PRIVATE
        PICO_BUILD=1
        MBEDTLS_CONFIG_FILE="mbedtls_config.h"
    )

    target_include_directories(pico_passkey PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${MBEDTLS_ROOT}/include
        ${MBEDTLS_ROOT}/library
    )

    target_link_libraries(pico_passkey PRIVATE
        pico_stdlib
        pico_rand
        pico_unique_id
        hardware_flash
        hardware_sync
        hardware_structs
        tinyusb_device
        tinyusb_board
    )

    pico_enable_stdio_usb(pico_passkey 0)
    pico_enable_stdio_uart(pico_passkey 0)

    pico_add_extra_outputs(pico_passkey)
endif()
