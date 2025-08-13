#pragma once

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace dns_resolver {

/**
 * @brief DNS record types as defined in RFC 1035 and extensions
 */
enum class RecordType : uint16_t {
  A = 1,        // IPv4 address
  NS = 2,       // Name server
  CNAME = 5,    // Canonical name
  SOA = 6,      // Start of authority
  PTR = 12,     // Pointer record
  MX = 15,      // Mail exchange
  TXT = 16,     // Text record
  AAAA = 28,    // IPv6 address
  SRV = 33,     // Service record
  OPT = 41,     // EDNS(0) option
  DS = 43,      // Delegation signer
  RRSIG = 46,   // DNSSEC signature
  NSEC = 47,    // Next secure record
  DNSKEY = 48,  // DNS key record
  NSEC3 = 50,   // Next secure record version 3
  ANY = 255     // Any record type
};

/**
 * @brief DNS record classes as defined in RFC 1035
 */
enum class RecordClass : uint16_t {
  IN = 1,  // Internet
  CS = 2,  // CSNET (obsolete)
  CH = 3,  // CHAOS
  HS = 4   // Hesiod
};

/**
 * @brief DNS response codes as defined in RFC 1035
 */
enum class ResponseCode : uint8_t {
  NO_ERROR = 0,         // No error
  FORMAT_ERROR = 1,     // Format error
  SERVER_FAILURE = 2,   // Server failure
  NAME_ERROR = 3,       // Name error (NXDOMAIN)
  NOT_IMPLEMENTED = 4,  // Not implemented
  REFUSED = 5           // Refused
};

/**
 * @brief DNS header structure according to RFC 1035
 */
struct DnsHeader {
  uint16_t id;       // Query identifier
  uint16_t flags;    // Flags field
  uint16_t qdcount;  // Number of questions
  uint16_t ancount;  // Number of answer RRs
  uint16_t nscount;  // Number of authority RRs
  uint16_t arcount;  // Number of additional RRs

  // Flag manipulation methods
  bool is_response() const { return (flags & 0x8000) != 0; }
  uint8_t get_opcode() const { return (flags >> 11) & 0x0F; }
  bool is_authoritative() const { return (flags & 0x0400) != 0; }
  bool is_truncated() const { return (flags & 0x0200) != 0; }
  bool recursion_desired() const { return (flags & 0x0100) != 0; }
  bool recursion_available() const { return (flags & 0x0080) != 0; }
  uint8_t get_rcode() const { return flags & 0x000F; }

  void set_response(bool value) {
    if (value)
      flags |= 0x8000;
    else
      flags &= ~0x8000;
  }

  void set_opcode(uint8_t opcode) { flags = (flags & ~0x7800) | ((opcode & 0x0F) << 11); }

  void set_authoritative(bool value) {
    if (value)
      flags |= 0x0400;
    else
      flags &= ~0x0400;
  }

  void set_truncated(bool value) {
    if (value)
      flags |= 0x0200;
    else
      flags &= ~0x0200;
  }

  void set_recursion_desired(bool value) {
    if (value)
      flags |= 0x0100;
    else
      flags &= ~0x0100;
  }

  void set_recursion_available(bool value) {
    if (value)
      flags |= 0x0080;
    else
      flags &= ~0x0080;
  }

  void set_rcode(uint8_t rcode) { flags = (flags & ~0x000F) | (rcode & 0x000F); }
};

/**
 * @brief DNS question structure
 */
struct DnsQuestion {
  std::string qname;   // Query name
  RecordType qtype;    // Query type
  RecordClass qclass;  // Query class

  DnsQuestion() = default;
  DnsQuestion(const std::string &name, RecordType type, RecordClass cls)
      : qname(name), qtype(type), qclass(cls) {}
};

/**
 * @brief DNS resource record structure
 */
struct ResourceRecord {
  std::string name;            // Domain name
  RecordType type;             // Record type
  RecordClass rr_class;        // Record class
  uint32_t ttl;                // Time to live
  std::vector<uint8_t> rdata;  // Resource data

  ResourceRecord() = default;
  ResourceRecord(const std::string &n, RecordType t, RecordClass c, uint32_t ttl_val)
      : name(n), type(t), rr_class(c), ttl(ttl_val) {}

  // Convenience methods for common record types
  std::string get_a_record() const;
  std::string get_aaaa_record() const;
  std::string get_cname_record() const;
  std::string get_ns_record() const;
  std::string get_txt_record() const;
};

/**
 * @brief Complete DNS message structure
 */
struct DnsMessage {
  DnsHeader header;
  std::vector<DnsQuestion> questions;
  std::vector<ResourceRecord> answers;
  std::vector<ResourceRecord> authorities;
  std::vector<ResourceRecord> additionals;

  DnsMessage() = default;
};

/**
 * @brief DNS-related exceptions
 */
class DnsException : public std::exception {
public:
  explicit DnsException(const std::string &message) : message_(message) {}
  const char *what() const noexcept override { return message_.c_str(); }

private:
  std::string message_;
};

class NetworkException : public DnsException {
public:
  explicit NetworkException(const std::string &message) : DnsException(message) {}
};

class ProtocolException : public DnsException {
public:
  explicit ProtocolException(const std::string &message) : DnsException(message) {}
};

class TimeoutException : public NetworkException {
public:
  explicit TimeoutException(const std::string &message) : NetworkException(message) {}
};

class ParseException : public ProtocolException {
public:
  explicit ParseException(const std::string &message) : ProtocolException(message) {}
};

/**
 * @brief Utility functions for DNS operations
 */
namespace utils {

/**
 * @brief Convert a domain name to lowercase for case-insensitive comparison
 */
std::string normalize_domain_name(const std::string &domain);

/**
 * @brief Validate domain name according to RFC 1035 rules
 */
bool is_valid_domain_name(const std::string &domain);

/**
 * @brief Convert RecordType enum to string
 */
std::string record_type_to_string(RecordType type);

/**
 * @brief Convert string to RecordType enum
 */
RecordType string_to_record_type(const std::string &type_str);

/**
 * @brief Convert IPv4 address bytes to string
 */
std::string ipv4_to_string(const std::vector<uint8_t> &bytes);

/**
 * @brief Convert IPv6 address bytes to string
 */
std::string ipv6_to_string(const std::vector<uint8_t> &bytes);

/**
 * @brief Generate a random 16-bit query ID
 */
uint16_t generate_query_id();

/**
 * @brief Get current timestamp in seconds since epoch
 */
uint64_t get_current_timestamp();

/**
 * @brief Convert network byte order to host byte order (16-bit)
 */
uint16_t ntohs_safe(uint16_t value);

/**
 * @brief Convert host byte order to network byte order (16-bit)
 */
uint16_t htons_safe(uint16_t value);

/**
 * @brief Convert network byte order to host byte order (32-bit)
 */
uint32_t ntohl_safe(uint32_t value);

/**
 * @brief Convert host byte order to network byte order (32-bit)
 */
uint32_t htonl_safe(uint32_t value);

}  // namespace utils

}  // namespace dns_resolver
