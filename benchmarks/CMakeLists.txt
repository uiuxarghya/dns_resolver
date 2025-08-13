# Benchmarks CMakeLists.txt

# Find or fetch Google Benchmark
find_package(benchmark QUIET)

if(NOT benchmark_FOUND)
    # Try to find system-installed benchmark first
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(BENCHMARK benchmark)
    endif()

    if(NOT BENCHMARK_FOUND)
        # Download and build Google Benchmark if not found
        include(FetchContent)
        FetchContent_Declare(
            googlebenchmark
            GIT_REPOSITORY https://github.com/google/benchmark.git
            GIT_TAG v1.8.3
        )

        # Configure benchmark options
        set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable benchmark testing" FORCE)
        set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Disable gtest tests" FORCE)

        FetchContent_MakeAvailable(googlebenchmark)
    endif()
endif()

# Benchmark source files
set(BENCHMARK_SOURCES
    benchmark.cpp
)

# Create benchmark executable
add_executable(dns_resolver_benchmark ${BENCHMARK_SOURCES})

# Link benchmark dependencies
target_link_libraries(dns_resolver_benchmark
    PRIVATE
    benchmark::benchmark
    benchmark::benchmark_main
    Threads::Threads
)

# Include directories for benchmarks
target_include_directories(dns_resolver_benchmark
    PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

# Add source files that benchmarks depend on (excluding main.cpp)
target_sources(dns_resolver_benchmark
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

# Set C++23 standard for benchmarks
set_target_properties(dns_resolver_benchmark PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# Add compiler-specific flags for benchmarks
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(dns_resolver_benchmark PRIVATE -Wno-restrict)
endif()

# Custom benchmark targets
add_custom_target(run_benchmarks
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/dns_resolver_benchmark --benchmark_out=benchmark_results.json --benchmark_out_format=json
    DEPENDS dns_resolver_benchmark
    COMMENT "Running performance benchmarks"
)

add_custom_target(benchmark_report
    COMMAND ${CMAKE_SOURCE_DIR}/benchmarks/run_benchmarks.sh
    DEPENDS dns_resolver_benchmark
    COMMENT "Running comprehensive benchmark suite"
)