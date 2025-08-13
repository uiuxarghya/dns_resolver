# DNS Resolver

A recursive DNS resolver implemented in C++ (C++23) from scratch.

## Overview

A complete DNS resolver that implements the full recursive resolution process by directly querying root servers, TLD servers, and authoritative servers without using OS-provided resolver functions. It follows RFC standards and provides high performance with intelligent caching.

> 📖 **For detailed documentation, tutorials, and API reference, visit [DNS Resolver Documentation](https://github.com/uiuxarghya/dns_resolver/wiki/)**

## ✨ Features

- **Full Recursive Resolution**: Manually implements the complete DNS resolution chain from root servers to authoritative servers
- **RFC Compliance**: Strictly follows DNS protocol specifications (RFC 1035, 1034, 2181, 4034, 7766)
- **Modern C++**: Uses latest C++ (C++23) features with proper RAII and memory management
- **High Performance**: Intelligent caching with TTL management and LRU eviction
- **Thread Safety**: Concurrent DNS queries with proper synchronization
- **Comprehensive Testing**: Unit tests, integration tests, and benchmarking suite
- **Production Ready**: Proper error handling, logging, and monitoring capabilities
- **Easy Configuration**: Environment variables and command-line options

## Supported Record Types

| Type      | Description           | Example                                   |
| --------- | --------------------- | ----------------------------------------- |
| **A**     | IPv4 addresses        | `./dns_resolver example.com`              |
| **AAAA**  | IPv6 addresses        | `./dns_resolver -t AAAA example.com`      |
| **CNAME** | Canonical names       | `./dns_resolver -t CNAME www.example.com` |
| **NS**    | Name servers          | `./dns_resolver -t NS example.com`        |
| **MX**    | Mail exchange         | `./dns_resolver -t MX example.com`        |
| **TXT**   | Text records          | `./dns_resolver -t TXT example.com`       |
| **SOA**   | Start of authority    | `./dns_resolver -t SOA example.com`       |
| **ANY**   | All available records | `./dns_resolver -t ANY example.com`       |

## Requirements

- C++23 compatible compiler (GCC 12+ or Clang 15+)
- CMake 3.20 or higher
- POSIX-compliant system (Linux, macOS, Unix)
- Internet connection for DNS queries

## Building

```bash
# Clone the repository
git clone https://github.com/uiuxarghya/dns_resolver.git
cd dns_resolver

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build the project
make -j$(nproc)

# Run tests
make test

# Install (optional)
sudo make install
```

## Usage

### Basic Usage

```bash
# Resolve a domain name
./dns_resolver example.com

# Resolve with verbose output showing resolution path
./dns_resolver -v example.com

# Specify query type
./dns_resolver -t AAAA example.com

# Query any record type
./dns_resolver -t ANY example.com
```

### Command Line Options

| Option                | Description                                        | Default |
| --------------------- | -------------------------------------------------- | ------- |
| `-v, --verbose`       | Show detailed resolution path                      | false   |
| `-t, --type <TYPE>`   | Query type (A, AAAA, CNAME, NS, MX, TXT, SOA, ANY) | A       |
| `-a, --all`           | Resolve both A and AAAA records                    | false   |
| `-T, --timeout <SEC>` | Query timeout in seconds                           | 5       |
| `-h, --help`          | Show help message                                  | -       |
| `--version`           | Show version information                           | -       |

### Examples

```bash
# Basic A record lookup
$ ./dns_resolver example.com
93.184.216.34

# Verbose resolution showing the full path
$ ./dns_resolver -v example.com
Querying root server 198.41.0.4 for example.com
Received referral to .com TLD servers
Querying TLD server 192.5.6.30 for example.com
Received referral to authoritative servers
Querying authoritative server 93.184.216.119 for example.com
Final answer: 93.184.216.34

# IPv6 lookup
$ ./dns_resolver -t AAAA example.com
2606:2800:220:1:248:1893:25c8:1946

# Resolve both A and AAAA records
$ ./dns_resolver --all example.com
142.250.191.14
2607:f8b0:4004:c1b::65
```

## Configuration

DNS Resolver can be configured using environment variables:

| Variable                           | Description                        | Default |
| ---------------------------------- | ---------------------------------- | ------- |
| `DNS_RESOLVER_UDP_TIMEOUT`         | UDP query timeout (seconds)        | 5       |
| `DNS_RESOLVER_TCP_TIMEOUT`         | TCP query timeout (seconds)        | 10      |
| `DNS_RESOLVER_MAX_CACHE_SIZE`      | Maximum cache entries              | 10000   |
| `DNS_RESOLVER_MAX_RECURSION_DEPTH` | Maximum recursion depth            | 16      |
| `DNS_RESOLVER_ENABLE_IPV6`         | Enable IPv6 queries (true/false)   | true    |
| `DNS_RESOLVER_VERBOSE`             | Enable verbose output (true/false) | false   |
| `DNS_RESOLVER_LOG_LEVEL`           | Log level (debug/info/warn/error)  | info    |

### Example Configuration

```bash
# Set custom timeouts
export DNS_RESOLVER_UDP_TIMEOUT=10
export DNS_RESOLVER_TCP_TIMEOUT=20

# Increase cache size
export DNS_RESOLVER_MAX_CACHE_SIZE=50000

# Enable verbose mode by default
export DNS_RESOLVER_VERBOSE=true

# Run with custom configuration
./dns_resolver example.com
```

## Architecture

DNS Resolver is designed with a modular architecture:

- **Resolver Engine**: Core recursive resolution logic
- **Packet Builder/Parser**: DNS protocol implementation
- **Network Layer**: UDP/TCP communication with DNS servers
- **Cache System**: Intelligent caching with TTL management
- **Configuration**: Root servers and system configuration

## Performance

DNS Resolver is optimized for performance:

- Sub-second resolution for most queries
- Intelligent caching reduces redundant queries
- Concurrent query processing
- Memory-efficient implementation
- Benchmarking tools included for performance analysis

## Testing

Comprehensive testing suite included:

```bash
# Run all tests
cd build
./tests/dns_resolver_tests

# Run specific test suites
./tests/dns_resolver_tests --gtest_filter="ResolverTest.*"
./tests/dns_resolver_tests --gtest_filter="CacheTest.*"
./tests/dns_resolver_tests --gtest_filter="PacketTest.*"

# Run benchmarks
./benchmarks/dns_resolver_benchmark

# Run with verbose output
./tests/dns_resolver_tests --gtest_output=xml:test_results.xml
```

## License

This project is licensed under the BSD-3-Clause License - see the [LICENSE](LICENSE) file for details.

## Author

**Arghya Ghosh** ([@uiuxarghya](https://github.com/uiuxarghya))

## Acknowledgments

- RFC authors for DNS protocol specifications
- Root server operators for maintaining DNS infrastructure
- C++ standards committee for modern language features
