include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.2
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(Catch2)

add_executable(sigscan_tests
    test_parse.cpp
    test_scan.cpp
    test_pe.cpp
    test_resolve.cpp
)
target_include_directories(sigscan_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sigscan_tests PRIVATE sigscan sigscan_warnings Catch2::Catch2WithMain)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(sigscan_tests)
