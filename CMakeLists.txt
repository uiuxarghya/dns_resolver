cmake_minimum_required(VERSION 3.20)

project(DNSResolver
    VERSION 1.0.0
    DESCRIPTION "A recursive DNS resolver written in modern C++ (C++23)"
    LANGUAGES CXX
)

# Set C++23 standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set default build type to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler-specific options
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Wpedantic -fsanitize=address,undefined")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Wall -Wextra -Wno-restrict")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Wpedantic -fsanitize=address,undefined")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Wall -Wextra")
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_SOURCE_DIR}/include)

# Find required packages
find_package(Threads REQUIRED)

# Source files
set(DNSRESOLVER_SOURCES
    src/main.cpp
    src/cli/cli_parser.cpp
    src/cli/application.cpp
    src/cli/output_formatter.cpp
    src/resolver/resolver.cpp
    src/resolver/query_engine.cpp
    src/resolver/response_processor.cpp
    src/resolver/recursion_handler.cpp
    src/resolver/packet_builder.cpp
    src/resolver/packet_parser.cpp
    src/resolver/cache.cpp
    src/resolver/utils.cpp
    src/net/udp_client.cpp
    src/net/tcp_client.cpp
    src/config/config.cpp
)

# Create the main executable (CLI-friendly name)
add_executable(dns_resolver ${DNSRESOLVER_SOURCES})

# Link libraries
target_link_libraries(dns_resolver PRIVATE Threads::Threads)

# Set target properties
set_target_properties(dns_resolver PROPERTIES
    OUTPUT_NAME "dns_resolver"
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# Enable testing
enable_testing()

# Add subdirectories
add_subdirectory(tests)
add_subdirectory(benchmarks)

# Install targets (binary in bin/)
install(TARGETS dns_resolver
    RUNTIME DESTINATION bin
)

# CPack configuration for packaging
set(CPACK_PACKAGE_NAME "DNS Resolver")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VENDOR "Arghya Ghosh")
set(CPACK_PACKAGE_CONTACT "uiuxarghya")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")

include(CPack)
