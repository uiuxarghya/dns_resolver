# DNS Packet Format Implementation

This document details the DNS packet format implementation in DNS Resolver according to RFC 1035.

## DNS Message Structure

```
    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
```

## Header Section (12 bytes)

### Header Format

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

### Header Fields

| Field   | Size    | Description                                                  |
| ------- | ------- | ------------------------------------------------------------ |
| ID      | 16 bits | Query identifier for matching requests/responses             |
| QR      | 1 bit   | Query (0) or Response (1)                                    |
| Opcode  | 4 bits  | Operation code (0=standard query, 1=inverse query, 2=status) |
| AA      | 1 bit   | Authoritative Answer flag                                    |
| TC      | 1 bit   | Truncation flag (response was truncated)                     |
| RD      | 1 bit   | Recursion Desired                                            |
| RA      | 1 bit   | Recursion Available                                          |
| Z       | 3 bits  | Reserved (must be zero)                                      |
| RCODE   | 4 bits  | Response code (0=no error, 3=name error, etc.)               |
| QDCOUNT | 16 bits | Number of questions                                          |
| ANCOUNT | 16 bits | Number of answer RRs                                         |
| NSCOUNT | 16 bits | Number of authority RRs                                      |
| ARCOUNT | 16 bits | Number of additional RRs                                     |

### C++ Header Implementation

```cpp
struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    // Flag manipulation methods
    bool is_response() const { return (flags & 0x8000) != 0; }
    uint8_t get_opcode() const { return (flags >> 11) & 0x0F; }
    bool is_authoritative() const { return (flags & 0x0400) != 0; }
    bool is_truncated() const { return (flags & 0x0200) != 0; }
    bool recursion_desired() const { return (flags & 0x0100) != 0; }
    bool recursion_available() const { return (flags & 0x0080) != 0; }
    uint8_t get_rcode() const { return flags & 0x000F; }
};
```

## Question Section

### Question Format

```
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     QNAME                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### Question Fields

| Field  | Description                                                 |
| ------ | ----------------------------------------------------------- |
| QNAME  | Domain name (variable length, encoded with length prefixes) |
| QTYPE  | Query type (A=1, AAAA=28, CNAME=5, etc.)                    |
| QCLASS | Query class (IN=1 for Internet)                             |

### Domain Name Encoding

Domain names are encoded as a sequence of labels, each prefixed by its length:

```
Example: "www.example.com" becomes:
[3]www[7]example[3]com[0]

Hex representation:
03 77 77 77 07 65 78 61 6D 70 6C 65 03 63 6F 6D 00
```

### C++ Question Implementation

```cpp
struct DnsQuestion {
    std::string qname;
    uint16_t qtype;
    uint16_t qclass;
};

enum class RecordType : uint16_t {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    ANY = 255
};

enum class RecordClass : uint16_t {
    IN = 1,    // Internet
    CS = 2,    // CSNET (obsolete)
    CH = 3,    // CHAOS
    HS = 4     // Hesiod
};
```

## Resource Record Format

### RR Format

```
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                      NAME                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### RR Fields

| Field    | Size     | Description                            |
| -------- | -------- | -------------------------------------- |
| NAME     | Variable | Domain name (with compression)         |
| TYPE     | 16 bits  | Resource record type                   |
| CLASS    | 16 bits  | Resource record class                  |
| TTL      | 32 bits  | Time to live in seconds                |
| RDLENGTH | 16 bits  | Length of RDATA field                  |
| RDATA    | Variable | Resource data (format depends on TYPE) |

### C++ Resource Record Implementation

```cpp
struct ResourceRecord {
    std::string name;
    uint16_t type;
    uint16_t rr_class;
    uint32_t ttl;
    std::vector<uint8_t> rdata;

    // Convenience methods for common types
    std::string get_a_record() const;
    std::string get_aaaa_record() const;
    std::string get_cname_record() const;
    std::string get_ns_record() const;
};
```

## RDATA Formats

### A Record (IPv4 Address)

```
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ADDRESS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

4 bytes representing IPv4 address in network byte order.

### AAAA Record (IPv6 Address)

```
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    |                    ADDRESS                    |
    |                                               |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

16 bytes representing IPv6 address in network byte order.

### CNAME Record

```
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     CNAME                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

Domain name (with compression) pointing to the canonical name.

### NS Record

```
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    NSDNAME                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

Domain name (with compression) of the authoritative name server.

## Name Compression

### Compression Pointers

To reduce packet size, domain names can be compressed using pointers:

```
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | 1  1|                OFFSET                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

When the first two bits are 11, the remaining 14 bits specify an offset from the start of the message.

### Compression Example

```
Original packet with "www.example.com" and "mail.example.com":
- "www.example.com" at offset 12
- "mail.example.com" can reference "example.com" part

Compressed:
- "www.example.com": [3]www[7]example[3]com[0]
- "mail.example.com": [4]mail[C0][16] (pointer to offset 16)
```

### C++ Compression Implementation

```cpp
class NameCompression {
public:
    void encode_name(const std::string& name, std::vector<uint8_t>& buffer);
    std::string decode_name(const std::vector<uint8_t>& packet, size_t& offset);

private:
    std::unordered_map<std::string, size_t> compression_map_;
    void add_compression_entry(const std::string& name, size_t offset);
    bool find_compression_target(const std::string& name, size_t& offset);
};
```

## Packet Building Process

### Query Packet Construction

1. **Initialize Header:**

   - Generate random query ID
   - Set QR=0 (query), RD=1 (recursion desired)
   - Set QDCOUNT=1, others=0

2. **Add Question:**

   - Encode domain name with length prefixes
   - Add QTYPE and QCLASS

3. **Finalize:**
   - Convert to network byte order
   - Return packet bytes

### Response Packet Parsing

1. **Parse Header:**

   - Extract all header fields
   - Validate response ID matches query
   - Check for errors (RCODE)

2. **Parse Questions:**

   - Skip question section (already known)
   - Handle name compression

3. **Parse Resource Records:**

   - Extract answer, authority, and additional sections
   - Decode compressed names
   - Parse RDATA based on record type

4. **Extract Results:**
   - Collect IP addresses from A/AAAA records
   - Follow CNAME chains
   - Extract NS records for referrals

## Error Handling

### Malformed Packet Detection

- Invalid compression pointers (loops, out of bounds)
- Truncated packets (insufficient data)
- Invalid record types or classes
- Inconsistent section counts

### Recovery Strategies

- Skip malformed records and continue parsing
- Log errors for debugging
- Return partial results when possible
- Fail gracefully with informative error messages
