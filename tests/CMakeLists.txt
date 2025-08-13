# Tests CMakeLists.txt

# Find GoogleTest
find_package(GTest QUIET)

if(NOT GTest_FOUND)
    # Try to find system-installed GoogleTest first
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(GTEST gtest)
        pkg_check_modules(GTEST_MAIN gtest_main)
    endif()

    if(NOT GTEST_FOUND)
        # Download and build GoogleTest if not found
        include(FetchContent)
        FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG v1.14.0
        )

        # For Windows: Prevent overriding the parent project's compiler/linker settings
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()
endif()

# Test source files
set(TEST_SOURCES
    test_main.cpp
    test_resolver.cpp
    test_cache.cpp
    test_packet.cpp
    test_integration.cpp
)

# Create test executable
add_executable(dns_resolver_tests ${TEST_SOURCES})

# Link test dependencies
target_link_libraries(dns_resolver_tests
    PRIVATE
    gtest
    gtest_main
    gmock
    gmock_main
    Threads::Threads
)

# Include directories for tests
target_include_directories(dns_resolver_tests
    PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

# Add source files that tests depend on (excluding main.cpp)
target_sources(dns_resolver_tests
    PRIVATE
    ${CMAKE_SOURCE_DIR}/src/resolver/resolver.cpp
    ${CMAKE_SOURCE_DIR}/src/resolver/query_engine.cpp
    ${CMAKE_SOURCE_DIR}/src/resolver/response_processor.cpp
    ${CMAKE_SOURCE_DIR}/src/resolver/recursion_handler.cpp
    ${CMAKE_SOURCE_DIR}/src/resolver/packet_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/resolver/packet_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/resolver/cache.cpp
    ${CMAKE_SOURCE_DIR}/src/resolver/utils.cpp
    ${CMAKE_SOURCE_DIR}/src/net/udp_client.cpp
    ${CMAKE_SOURCE_DIR}/src/net/tcp_client.cpp
    ${CMAKE_SOURCE_DIR}/src/config/config.cpp
)

# Set C++23 standard for tests
set_target_properties(dns_resolver_tests PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# Add compiler-specific flags for tests
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(dns_resolver_tests PRIVATE -Wno-restrict)
endif()

# Discover and register tests
include(GoogleTest)
gtest_discover_tests(dns_resolver_tests)

# Add custom test targets
add_custom_target(test_verbose
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/dns_resolver_tests --gtest_output=xml:test_results.xml
    DEPENDS dns_resolver_tests
    COMMENT "Running tests with verbose output"
)

add_custom_target(test_coverage
    COMMAND gcov ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/dns_resolver_tests.dir/src/*.gcno
    DEPENDS dns_resolver_tests
    COMMENT "Generating code coverage report"
)