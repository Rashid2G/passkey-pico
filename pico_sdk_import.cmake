# ====================================================================================
# Pico SDK Import File (supports PICO_SDK_PATH or local .sdk/pico-sdk)
# ====================================================================================

if (DEFINED ENV{PICO_SDK_PATH} AND (NOT PICO_SDK_PATH))
    set(PICO_SDK_PATH $ENV{PICO_SDK_PATH})
endif ()

if (NOT PICO_SDK_PATH)
    set(_LOCAL_SDK_PATH "${CMAKE_CURRENT_LIST_DIR}/.sdk/pico-sdk")
    if (EXISTS "${_LOCAL_SDK_PATH}/pico_sdk_init.cmake")
        set(PICO_SDK_PATH "${_LOCAL_SDK_PATH}")
    endif ()
endif ()

if (NOT PICO_SDK_PATH)
    message(FATAL_ERROR
        "Pico SDK path was not specified. Run ./scripts/bootstrap_sdk.sh or set PICO_SDK_PATH."
    )
endif ()

get_filename_component(PICO_SDK_PATH "${PICO_SDK_PATH}" REALPATH BASE_DIR "${CMAKE_BINARY_DIR}")
if (NOT EXISTS "${PICO_SDK_PATH}")
    message(FATAL_ERROR "Directory '${PICO_SDK_PATH}' not found")
endif ()

set(PICO_SDK_INIT_CMAKE_FILE "${PICO_SDK_PATH}/pico_sdk_init.cmake")
if (NOT EXISTS "${PICO_SDK_INIT_CMAKE_FILE}")
    message(FATAL_ERROR "Directory '${PICO_SDK_PATH}' does not contain pico_sdk_init.cmake")
endif ()

set(PICO_SDK_PATH "${PICO_SDK_PATH}" CACHE PATH "Path to the Raspberry Pi Pico SDK" FORCE)

if (NOT PICO_TOOLCHAIN_PATH AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/.sdk/arm-gnu-toolchain/bin/arm-none-eabi-gcc")
    set(PICO_TOOLCHAIN_PATH "${CMAKE_CURRENT_LIST_DIR}/.sdk/arm-gnu-toolchain" CACHE PATH "Path to ARM GCC toolchain" FORCE)
endif ()

include("${PICO_SDK_INIT_CMAKE_FILE}")
