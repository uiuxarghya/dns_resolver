# RFC References and Compliance

This document outlines the RFC standards that DNS Resolver implements and how it ensures compliance.

## Core DNS RFCs

### RFC 1034 - Domain Names - Concepts and Facilities (November 1987)

**Key Concepts Implemented:**

- Hierarchical domain name space structure
- Domain name syntax and semantics
- Name server delegation model
- Resolver behavior and algorithms

**Compliance Details:**

- Domain names are case-insensitive (Section 3.1)
- Maximum label length of 63 characters (Section 2.3.4)
- Maximum domain name length of 255 characters (Section 2.3.4)
- Proper handling of the root domain (empty label)
- Implementation of the delegation model for name resolution

### RFC 1035 - Domain Names - Implementation and Specification (November 1987)

**Key Features Implemented:**

- Complete DNS message format specification
- Resource record formats and types
- Standard query and response processing
- Name compression algorithm

**Message Format Compliance:**

```
Header Section:
- ID: 16-bit identifier for matching queries and responses
- QR: Query/Response flag (0=query, 1=response)
- OPCODE: 4-bit operation code (0=standard query)
- AA: Authoritative Answer flag
- TC: Truncation flag (triggers TCP fallback)
- RD: Recursion Desired flag (always set to 1)
- RA: Recursion Available flag
- Z: Reserved bits (must be zero)
- RCODE: 4-bit response code

Question Section:
- QNAME: Domain name (with compression support)
- QTYPE: Query type (A=1, AAAA=28, etc.)
- QCLASS: Query class (IN=1 for Internet)

Answer/Authority/Additional Sections:
- NAME: Domain name (with compression)
- TYPE: Resource record type
- CLASS: Resource record class
- TTL: Time to live in seconds
- RDLENGTH: Length of RDATA
- RDATA: Resource data
```

**Name Compression (Section 4.1.4):**

- Implements pointer compression for domain names
- Handles compression pointers correctly
- Prevents infinite loops in malformed packets

### RFC 2181 - Clarifications to the DNS Specification (July 1997)

**Key Clarifications Implemented:**

- TTL handling and decrementing over time
- Authoritative vs non-authoritative responses
- Case preservation in domain names
- Multiple RRs of the same type handling

**TTL Management:**

- Cache entries have their TTL decremented over time
- Expired entries are removed from cache
- Minimum TTL of 0 seconds is respected
- TTL values are never negative

**Authority Handling:**

- Distinguish between authoritative and cached responses
- Prefer authoritative answers over cached data
- Proper handling of AA flag in responses

### RFC 4034 - Resource Records for DNS Security Extensions (March 2005)

**DNSSEC Field Parsing:**
While DNS Resolver doesn't perform DNSSEC validation, it correctly parses DNSSEC-related fields:

- RRSIG records (type 46)
- DNSKEY records (type 48)
- DS records (type 43)
- NSEC records (type 47)
- NSEC3 records (type 50)

**Implementation Notes:**

- DNSSEC records are parsed but not validated
- Additional section may contain DNSSEC records
- OPT pseudo-RR handling for EDNS(0)

### RFC 7766 - DNS Transport over TCP (March 2016)

**TCP Fallback Implementation:**

- Automatic fallback to TCP when TC (truncation) bit is set
- Proper TCP message framing with 2-byte length prefix
- Connection management and timeout handling
- Support for larger responses over TCP

**TCP Message Format:**

```
+-----+---------+
| LEN |  MESSAGE |
+-----+---------+
```

Where LEN is a 16-bit length field in network byte order.

## Additional RFCs Considered

### RFC 1123 - Requirements for Internet Hosts (October 1989)

**Host Requirements:**

- Case-insensitive domain name comparison
- Proper handling of CNAME records
- Timeout and retry behavior
- Error handling requirements

### RFC 3596 - DNS Extensions to Support IP Version 6 (October 2003)

**IPv6 Support:**

- AAAA record type (type 28) for IPv6 addresses
- Proper IPv6 address formatting
- Dual-stack operation (IPv4 and IPv6)

### RFC 6891 - Extension Mechanisms for DNS (EDNS(0)) (April 2013)

**EDNS(0) Awareness:**

- Recognition of OPT pseudo-RR in additional section
- Proper handling of extended RCODE
- UDP payload size negotiation awareness

## Compliance Testing

### Test Cases for RFC Compliance

1. **Message Format Tests:**

   - Verify correct header field encoding/decoding
   - Test name compression and decompression
   - Validate resource record parsing

2. **Protocol Behavior Tests:**

   - Test recursive resolution algorithm
   - Verify proper handling of referrals
   - Test CNAME following behavior

3. **Error Handling Tests:**

   - Test response to malformed packets
   - Verify timeout and retry behavior
   - Test handling of various RCODE values

4. **Cache Behavior Tests:**
   - Verify TTL decrementing
   - Test cache expiration
   - Validate negative caching

### Validation Tools

```bash
# Test with dig for comparison
dig @localhost -p 5353 example.com

# Test with nslookup
nslookup example.com localhost

# Packet capture for analysis
tcpdump -i lo -w dns_capture.pcap port 53
```

## Non-Compliance Areas

### Intentional Limitations

1. **DNSSEC Validation:** Not implemented (parsing only)
2. **Dynamic Updates:** Not supported (RFC 2136)
3. **Zone Transfers:** Not applicable for resolver
4. **Multicast DNS:** Not implemented (RFC 6762)

### Future Enhancements

1. **EDNS(0) Full Support:** Currently basic awareness only
2. **DNS over HTTPS:** Could be added (RFC 8484)
3. **DNS over TLS:** Could be added (RFC 7858)
4. **DNSSEC Validation:** Full validation support

## Standards Compliance Verification

### Automated Testing

```cpp
// Example compliance test
TEST(RfcCompliance, MessageFormatRfc1035) {
    PacketBuilder builder;
    auto packet = builder
        .set_id(0x1234)
        .set_flags(0x0100)  // Standard query, RD=1
        .add_question("example.com", RecordType::A, RecordClass::IN)
        .build();

    // Verify header format
    EXPECT_EQ(packet[0], 0x12);  // ID high byte
    EXPECT_EQ(packet[1], 0x34);  // ID low byte
    EXPECT_EQ(packet[2], 0x01);  // Flags high byte
    EXPECT_EQ(packet[3], 0x00);  // Flags low byte
}
```

### Manual Verification

1. **Wireshark Analysis:** Capture and analyze DNS packets
2. **Interoperability Testing:** Test against major DNS servers
3. **Conformance Tools:** Use DNS testing utilities
4. **Reference Implementation Comparison:** Compare with BIND, Unbound

## Documentation References

- [RFC 1034](https://tools.ietf.org/html/rfc1034) - Domain Names - Concepts and Facilities
- [RFC 1035](https://tools.ietf.org/html/rfc1035) - Domain Names - Implementation and Specification
- [RFC 2181](https://tools.ietf.org/html/rfc2181) - Clarifications to the DNS Specification
- [RFC 4034](https://tools.ietf.org/html/rfc4034) - Resource Records for DNS Security Extensions
- [RFC 7766](https://tools.ietf.org/html/rfc7766) - DNS Transport over TCP
- [IANA DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
