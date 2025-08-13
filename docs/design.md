# DNS Resolver Design Document

## Architecture Overview

DNS Resolver implements a modular, layered architecture that separates concerns and provides clean interfaces between components.

### Core Components

```
┌─────────────────┐
│   CLI Interface │
├─────────────────┤
│ Resolver Engine │
├─────────────────┤
│ Packet Builder/ │
│     Parser      │
├─────────────────┤
│ Network Layer   │
├─────────────────┤
│ Cache System    │
└─────────────────┘
```

## Resolver Engine

The core recursive resolution logic implements the DNS hierarchy traversal:

1. **Query Initialization**: Generate unique query ID and prepare question
2. **Root Server Query**: Start with one of the 13 root servers
3. **Referral Following**: Follow NS records through TLD and authoritative servers
4. **CNAME Resolution**: Handle canonical name redirections
5. **Answer Processing**: Extract final IP addresses from authoritative responses

### Resolution Algorithm

```cpp
class Resolver {
public:
    std::vector<std::string> resolve(const std::string& domain, RecordType type);

private:
    std::vector<std::string> resolve_recursive(
        const std::string& domain,
        RecordType type,
        const std::vector<std::string>& servers,
        int depth = 0
    );
};
```

## Packet Format Implementation

### DNS Header Structure (RFC 1035)

```
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### Packet Builder Design

```cpp
class PacketBuilder {
public:
    PacketBuilder& set_id(uint16_t id);
    PacketBuilder& set_flags(uint16_t flags);
    PacketBuilder& add_question(const std::string& name, RecordType type, RecordClass cls);
    std::vector<uint8_t> build();

private:
    void encode_name(const std::string& name, std::vector<uint8_t>& buffer);
    void write_uint16(uint16_t value, std::vector<uint8_t>& buffer);
};
```

## Network Layer

### UDP Client Implementation

Primary transport for DNS queries with automatic timeout and retry logic:

```cpp
class UdpClient {
public:
    UdpClient(std::chrono::seconds timeout = std::chrono::seconds(5));
    std::vector<uint8_t> query(const std::string& server, uint16_t port,
                               const std::vector<uint8_t>& packet);

private:
    int socket_fd_;
    std::chrono::seconds timeout_;
};
```

### TCP Client Implementation

Fallback transport for truncated responses (TC bit set):

```cpp
class TcpClient {
public:
    TcpClient(std::chrono::seconds timeout = std::chrono::seconds(10));
    std::vector<uint8_t> query(const std::string& server, uint16_t port,
                               const std::vector<uint8_t>& packet);
};
```

## Cache System

### Cache Architecture

Thread-safe LRU cache with TTL management:

```cpp
class DnsCache {
public:
    struct CacheEntry {
        std::vector<std::string> records;
        std::chrono::system_clock::time_point expiry;
        bool is_negative;  // For NXDOMAIN/NODATA
    };

    std::optional<CacheEntry> get(const std::string& key);
    void put(const std::string& key, const CacheEntry& entry);
    void cleanup_expired();

private:
    std::unordered_map<std::string, CacheEntry> cache_;
    std::list<std::string> lru_list_;
    std::unordered_map<std::string, std::list<std::string>::iterator> lru_map_;
    std::shared_mutex cache_mutex_;
    size_t max_size_;
};
```

### Cache Key Generation

Cache keys include query name, type, and class to ensure uniqueness:

```
cache_key = domain_name + ":" + record_type + ":" + record_class
```

## Error Handling

### Exception Hierarchy

```cpp
class DnsException : public std::exception {};
class NetworkException : public DnsException {};
class ProtocolException : public DnsException {};
class TimeoutException : public NetworkException {};
class ParseException : public ProtocolException {};
```

### Error Recovery

- Network timeouts: Retry with different servers
- Malformed packets: Log and continue with next server
- NXDOMAIN: Cache negative response and return empty result
- Server failures: Try alternative servers in the same level

## Threading Model

### Concurrent Query Processing

```cpp
class ConcurrentResolver {
public:
    std::future<std::vector<std::string>> resolve_async(
        const std::string& domain, RecordType type);

private:
    std::thread_pool pool_;
    DnsCache shared_cache_;
};
```

## Configuration Management

### Root Servers Configuration

Hard-coded list of root servers with IPv4 and IPv6 addresses:

```cpp
namespace config {
    const std::vector<std::string> ROOT_SERVERS = {
        "198.41.0.4",      // a.root-servers.net
        "199.9.14.201",    // b.root-servers.net
        "192.33.4.12",     // c.root-servers.net
        // ... all 13 root servers
    };
}
```

### Runtime Configuration

```cpp
struct Config {
    std::chrono::seconds query_timeout{5};
    size_t max_cache_size{10000};
    int max_recursion_depth{16};
    bool enable_ipv6{true};
    LogLevel log_level{LogLevel::INFO};
};
```

## Performance Considerations

### Memory Management

- Use smart pointers for automatic memory management
- Implement move semantics for large data structures
- Pool socket connections where possible
- Efficient string handling with string_view

### Network Optimization

- Connection pooling for TCP queries
- Parallel queries to multiple servers
- Intelligent server selection based on response times
- IPv6 fallback for better connectivity

### Cache Optimization

- LRU eviction for memory efficiency
- Background TTL cleanup to prevent memory leaks
- Read-write locks for concurrent access
- Negative caching to avoid repeated failed queries
