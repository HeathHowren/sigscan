# 3.28 to match the rest of the Game Reversal Club tools; the library itself is
# header-only and needs far less.
cmake_minimum_required(VERSION 3.28)

project(sigscan VERSION 1.0.0 LANGUAGES CXX)

if(NOT MSVC)
    message(FATAL_ERROR "sigscan is developed and tested with MSVC. The single header itself is portable C++20; only this build is MSVC-only.")
endif()

get_property(_ss_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT _ss_multi_config AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Static CRT, so sigscan.exe runs on a clean Windows with no VC++ redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

option(SIGSCAN_BUILD_TESTS "Build the unit tests" ON)
option(SIGSCAN_BUILD_CLI "Build the sigscan command-line tool" ON)
option(SIGSCAN_BUILD_BENCH "Build the throughput benchmark" ON)
option(SIGSCAN_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)

# ---------------------------------------------------------------------------
# Warnings, first-party targets only
# ---------------------------------------------------------------------------

add_library(sigscan_warnings INTERFACE)
target_compile_options(sigscan_warnings INTERFACE /W4 /w44062 /permissive- /Zc:__cplusplus /utf-8)
if(SIGSCAN_WARNINGS_AS_ERRORS)
    target_compile_options(sigscan_warnings INTERFACE /WX)
endif()

# ---------------------------------------------------------------------------
# The library: one header, no dependencies.
# ---------------------------------------------------------------------------

add_library(sigscan INTERFACE)
add_library(sigscan::sigscan ALIAS sigscan)
target_include_directories(sigscan INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(sigscan INTERFACE cxx_std_20)

# ---------------------------------------------------------------------------
# The CLI: sigscan.exe. Defines SIGSCAN_IMPLEMENTATION, so the live-process code
# (windows.h) is compiled here.
# ---------------------------------------------------------------------------

if(SIGSCAN_BUILD_CLI)
    add_executable(sigscan_cli cli/main.cpp)
    set_target_properties(sigscan_cli PROPERTIES OUTPUT_NAME sigscan)
    target_link_libraries(sigscan_cli PRIVATE sigscan sigscan_warnings)
    target_compile_definitions(sigscan_cli PRIVATE SIGSCAN_CLI_VERSION="${PROJECT_VERSION}")
endif()

# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

if(SIGSCAN_BUILD_BENCH)
    add_executable(sigscan_bench bench/bench.cpp)
    set_target_properties(sigscan_bench PROPERTIES OUTPUT_NAME sigscan-bench)
    target_link_libraries(sigscan_bench PRIVATE sigscan sigscan_warnings)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(SIGSCAN_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Package: a zip with the CLI and the header, plus the notices.
# ---------------------------------------------------------------------------

if(SIGSCAN_BUILD_CLI)
    install(TARGETS sigscan_cli RUNTIME DESTINATION .)
endif()
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/sigscan/sigscan.hpp DESTINATION include/sigscan)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/CHANGELOG.md
    ${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md
    DESTINATION .
)

set(CPACK_PACKAGE_NAME "sigscan")
set(CPACK_PACKAGE_VENDOR "Game Reversal Club")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
if(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
    set(CPACK_PACKAGE_FILE_NAME "sigscan-v${PROJECT_VERSION}-windows-x86")
else()
    set(CPACK_PACKAGE_FILE_NAME "sigscan-v${PROJECT_VERSION}-windows-x64")
endif()
set(CPACK_GENERATOR "ZIP")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Byte-signature scanner library and CLI")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
include(CPack)
